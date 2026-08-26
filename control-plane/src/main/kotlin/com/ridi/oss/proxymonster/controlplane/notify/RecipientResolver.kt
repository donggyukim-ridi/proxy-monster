package com.ridi.oss.proxymonster.controlplane.notify

import com.ridi.oss.proxymonster.controlplane.AccessRequest
import com.ridi.oss.proxymonster.controlplane.toApprovalResource
import com.ridi.oss.proxymonster.controlplane.RoleResolver
import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.SatisfiableVerdict
import org.slf4j.LoggerFactory

/**
 * Who should hear about a task (docs/notifications.md, "Who can approve"). Cedar answers "may bob approve
 * this", never "who may", so this asks [Authz.satisfiableAs] per active candidate and notifies anyone whose
 * verdict is not IMPOSSIBLE. Over-notifying costs a 403 the recipient was always going to get; missing a real
 * approver leaves the request waiting with nobody told. Pinned against the shipped policies in
 * RecipientResolverDbTest.
 */
class RecipientResolver(
    private val authz: Authz,
    private val roleResolver: RoleResolver,
    // Required, not defaulted: routing has to ask the same question the approve route asks, and a
    // tag-scoped permit is unsatisfiable against a Datasource with no tags on it. Defaulting this to empty
    // would let a caller silently route as though no policy were tag-scoped, which skips every eligible
    // approver instead of over-notifying — the one direction this class must never fail in.
    private val datasourceTagsFor: (AccessRequest) -> List<String>,
    private val candidateSource: () -> List<String>,
) {
    private val log = LoggerFactory.getLogger(RecipientResolver::class.java)

    /**
     * Everyone who could plausibly approve [req], plus [alwaysInclude] — the parties told how their own
     * request ended, whether or not they hold approval authority. A routing failure still keeps those.
     */
    fun recipientsFor(req: AccessRequest, alwaysInclude: Collection<String> = emptyList()): Set<String> {
        val eligible = runCatching { approverCandidates(req) }
            .onFailure { log.warn("notification routing failed for task={}", req.id, it) }
            .getOrDefault(emptySet())
        return (eligible + alwaysInclude.filter { it.isNotBlank() }).toSet()
    }

    private fun approverCandidates(req: AccessRequest): Set<String> {
        val resource = req.toApprovalResource()
        val datasourceTags = datasourceTagsFor(req)
        return candidateSource()
            .filter { candidate ->
                authz.satisfiableAs(
                    candidate,
                    roleResolver.resolve(candidate),
                    AuthzAction.TASK_APPROVE,
                    resource,
                    // The recipient's own request context is unknowable at routing time — the channel they will
                    // act on, their attested IP, and every tag DERIVED from those. Mark all three UNKNOWN, not
                    // pinned or absent: an absent attribute makes a conditioning permit deny and would drop a
                    // candidate who could in fact approve. The click runs the real decision with concrete values.
                    knownChannel = null,
                    unknownContextKeys = setOf("channel", "requester_ip", "tags"),
                    // The datasource's OWN tags, which are known here and are not the derived context tags
                    // marked unknown above. A tag-scoped approval permit needs them to be satisfiable at all.
                    datasourceTags = datasourceTags,
                ) != SatisfiableVerdict.IMPOSSIBLE
            }
            .toSet()
    }
}
