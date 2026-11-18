"use strict";

const { GuardCapability, SinkKind } = require("../semantics");
const { sinkModel, guardModel } = require("../model-factories");

const INJECTION_MODELS = Object.freeze([
  sinkModel({
    id: "java.ldap.search-filter", languages: ["java"],
    moduleNames: ["javax.naming.directory", "javax.naming.ldap"],
    qualifiedNames: ["DirContext.search", "InitialDirContext.search", "LdapContext.search", "InitialLdapContext.search"],
    receiverTypes: ["DirContext", "InitialDirContext", "LdapContext", "InitialLdapContext"],
    callNames: ["search"], callForms: ["instance-method"], patternReceiverAgnostic: true,
    taintArguments: [1], sinkKind: SinkKind.LDAP_QUERY, category: "ldap",
    requiredArguments: [{ index: 2 }],
    excludedArgumentTypes: [{ index: 1, types: ["Attributes", "BasicAttributes"], reason: "The Attributes overload searches data values rather than LDAP filter text." }],
  }),
  sinkModel({
    id: "php.ldap.search-filter", languages: ["php"], global: true, fallbackByCallName: true,
    moduleNames: [], qualifiedNames: ["ldap_search", "ldap_list", "ldap_read"],
    callNames: ["ldap_search", "ldap_list", "ldap_read"], callForms: ["function"],
    taintArguments: [2], sinkKind: SinkKind.LDAP_QUERY, category: "ldap",
    requiredArguments: [{ index: 2 }],
  }),
  sinkModel({
    id: "python.ldap.search-filter", languages: ["python"],
    moduleNames: ["ldap", "ldap.ldapobject"], qualifiedNames: ["LDAPObject.search_s", "LDAPObject.search", "LDAPObject.search_ext_s", "LDAPObject.search_ext"],
    receiverTypes: ["LDAPObject", "SimpleLDAPObject", "ReconnectLDAPObject"],
    callNames: ["search_s", "search", "search_ext_s", "search_ext"], callForms: ["instance-method"], patternReceiverAgnostic: true,
    taintArguments: [2], sinkKind: SinkKind.LDAP_QUERY, category: "ldap",
    requiredArguments: [{ index: 2 }],
  }),
  guardModel({
    id: "python.ldap.filter-escaping", languages: ["python"],
    moduleNames: ["ldap.filter"], qualifiedNames: ["ldap.filter.escape_filter_chars"],
    callNames: ["escape_filter_chars"], callForms: ["module-function", "function"],
    taintArguments: [0], guardCapabilities: [GuardCapability.LDAP_FILTER_ESCAPE],
    applicableSinkKinds: [SinkKind.LDAP_QUERY], returnsTaint: true,
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.flask.template-source", languages: ["python"],
    moduleNames: ["flask"], qualifiedNames: ["flask.render_template_string", "flask.stream_template_string"],
    callNames: ["render_template_string", "stream_template_string"], callForms: ["module-function", "function"],
    taintArguments: [0], sinkKind: SinkKind.TEMPLATE_RENDER, category: "template", requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.jinja.template-source", languages: ["python"],
    moduleNames: ["jinja2"], qualifiedNames: ["jinja2.Template"],
    callNames: ["Template"], callForms: ["module-function", "function"],
    taintArguments: [0], sinkKind: SinkKind.TEMPLATE_RENDER, category: "template", requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "php.twig.template-source", languages: ["php"],
    moduleNames: ["Twig"], qualifiedNames: ["Twig\\Environment.createTemplate"], receiverTypes: ["Twig\\Environment"],
    callNames: ["createTemplate"], callForms: ["instance-method"], patternReceiverAgnostic: true,
    taintArguments: [0], sinkKind: SinkKind.TEMPLATE_RENDER, category: "template",
  }),
]);

module.exports = { INJECTION_MODELS };
