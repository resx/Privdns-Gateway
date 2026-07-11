# Third-party frontend resources

The management PWA adapts the following MIT-licensed frontend structures to the PrivDNS Gateway API and visual system:

- MetaCubeX/MetaCubeXD `ProxyMasterDetail.vue` and proxy node components: policy group master-detail navigation, local node search, facets, current-node navigation, and compact node rows.
- Zephyruso/Zashboard `RuleCard.vue`, `ProxyGroup.vue`, and proxy node components: two-line rule presentation, expandable target policy groups, and inline member selection.

The adapted implementation does not include either project's API client, authentication, router, store, or complete application bundle. Local modifications preserve the gateway's HTTPS authentication and existing configuration transaction path.

See `MetaCubeXD-LICENSE.txt` and `Zashboard-LICENSE.txt` in this directory.
