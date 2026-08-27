/**
 * Kinyarwanda — the DEFAULT locale (05 §7: "Kinyarwanda (default), English,
 * French — full localisation, not just labels").
 *
 * This file is the SOURCE OF TRUTH for the key set: `MessageKey` is derived
 * from it (see ./types.ts), so `en` and `fr` fail to compile the moment they
 * drift. Add a key here first.
 *
 * Wording rules (05 §7, and 03 §7 for errors):
 * - Plain, everyday Kinyarwanda a non-technical citizen understands. Where a
 *   precise security term exists only in English/French jargon we choose the
 *   everyday phrasing and describe the effect instead of naming the mechanism
 *   (e.g. "urufunguzo rw'ibanga rutavamo" — "a secret key that cannot leave" —
 *   rather than transliterating "non-exportable private key").
 * - Error text NEVER explains which control failed (03 §7: a precise reason
 *   tells an attacker what to defeat). It says what the citizen can do next.
 * - No server-supplied string is ever shown raw; everything routes through here.
 *
 * Interpolation is `{name}` placeholders, filled by `t(key, params)`.
 */
export const rw = {
  // ── Common ────────────────────────────────────────────────────────────────
  // NOTE: the citizen-facing product name is still open decision #10; "SDID"
  // is a placeholder carried identically in all three locales.
  'common.appName': 'RwandaPass',
  'common.continue': 'Komeza',
  'common.cancel': 'Reka',
  'common.back': 'Subira inyuma',
  'common.retry': 'Ongera ugerageze',
  'common.close': 'Funga',
  'common.done': 'Byarangiye',
  'common.loading': 'Birimo gutunganywa...',
  'common.yes': 'Yego',
  'common.no': 'Oya',
  'common.help': 'Ubufasha',
  'common.errorTitle': 'Habaye ikibazo',

  // ── Language picker (first screen, before anything else — 05 §2) ──────────
  'language.title': 'Hitamo ururimi',
  'language.rw': 'Ikinyarwanda',
  'language.en': 'Icyongereza',
  'language.fr': 'Igifaransa',

  // ── Onboarding ────────────────────────────────────────────────────────────
  'onboarding.welcomeTitle': 'Murakaza neza',
  'onboarding.welcomeBody':
    'Iyi porogaramu ituma winjira muri serivisi za Leta ukoresheje isura cyangwa igikumwe cyawe, nta jambo ry’ibanga.',
  'onboarding.start': 'Tangira kwiyandikisha',

  // ── Enrolment · NID entry (03 §2) ─────────────────────────────────────────
  'enrol.nid.title': 'Andika nomero y’indangamuntu yawe',
  'enrol.nid.label': 'Nomero y’indangamuntu',
  'enrol.nid.help': 'Nomero igizwe n’imibare 16.',
  'enrol.nid.invalid': 'Nomero y’indangamuntu igomba kugira imibare 16.',
  'enrol.nid.privacyNote':
    'Nomero yawe ntibikwa kuri iyi telefone. Ikoreshwa rimwe gusa, mu kwemeza ko ari wowe.',

  // ── Enrolment · consent (08 §4 — our own consent artefact) ────────────────
  'enrol.consent.title': 'Uruhushya rwo kugenzura umwirondoro wawe',
  'enrol.consent.body':
    'Kugira ngo iyi telefone ibashe kukwinjiza muri serivisi za Leta, tugomba kubanza kwemeza ko ari wowe koko.',
  'enrol.consent.point.match': 'Isura yawe igereranywa n’iyanditse kuri NIDA, rimwe gusa.',
  'enrol.consent.point.noStore':
    'Ifoto y’isura yawe ntibikwa: ihita isibwa ako kanya nyuma yo kugereranya.',
  'enrol.consent.point.deviceKey':
    'Iyi telefone ibona urufunguzo rw’ibanga rutavamo, rufungurwa n’isura cyangwa igikumwe cyawe gusa.',
  'enrol.consent.point.revoke': 'Ushobora guhagarika iyi telefone igihe cyose ubishakiye.',
  'enrol.consent.agree': 'Ndabyemeye, komeza',
  'enrol.consent.decline': 'Sinabyemera',

  // ── Enrolment · face capture + liveness (03 §2 step 3, ISO 30107 L2) ──────
  'enrol.capture.title': 'Fata ifoto y’isura yawe',
  'enrol.capture.instruction':
    'Shyira isura yawe muri uruziga, urebe kuri kamera, uhumbye amaso rimwe.',
  'enrol.capture.liveness': 'Turimo kugenzura ko ari wowe ubwawe, atari ifoto.',
  'enrol.capture.capturing': 'Turimo gufata ifoto...',
  'enrol.capture.retake': 'Ongera ufate ifoto',

  // ── Enrolment · progress ──────────────────────────────────────────────────
  'enrol.progress.attesting': 'Turimo kugenzura umutekano w’iyi telefone...',
  'enrol.progress.generatingKey': 'Turimo gukora urufunguzo rw’umutekano...',
  'enrol.progress.matching': 'Turimo kugereranya isura yawe n’iyanditse...',
  'enrol.progress.activating': 'Turimo kwemeza iyi telefone...',

  // ── Enrolment · outcome ───────────────────────────────────────────────────
  'enrol.done.title': 'Byagenze neza',
  'enrol.done.body':
    'Iyi telefone ubu ni yo yemeza ko ari wowe. Ntuzongera gusabwa nomero y’indangamuntu.',
  'enrol.done.assurance': 'Urwego rw’ubwizerwe: {level}',
  'enrol.failed.title': 'Ntibishobotse kwiyandikisha',
  'enrol.failed.body':
    'Ongera ugerageze. Nibikomeza, saba ubufasha ku biro by’irangamimerere bikwegereye.',

  // ── Home ──────────────────────────────────────────────────────────────────
  'home.title': 'Ahabanza',
  'home.greeting': 'Muraho, {name}',
  'home.deviceStatus.active': 'Iyi telefone irakora',
  'home.deviceStatus.pending': 'Iyi telefone iracyategereje kwemezwa',
  'home.deviceStatus.revoked': 'Iyi telefone yarahagaritswe',
  'home.assuranceLabel': 'Urwego rw’ubwizerwe',
  'home.noPending': 'Nta cyo usabwa kwemeza ubu.',
  'home.pendingCount': 'Hari ibisabwa {count} bitegereje kwemezwa.',
  'home.recentActivity': 'Ibyakozwe vuba',
  'home.viewAll': 'Reba byose',
  'home.devices': 'Ibikoresho byanjye',
  'home.settings': 'Igenamiterere',
  'home.lastUsed': 'Byakoreshejwe bwa nyuma: {date}',

  // ── CIBA approval — SECURITY CRITICAL (04 §3, 05 §2, T7) ─────────────────
  'approval.title': 'Hari usaba kwinjira mu izina ryawe',
  'approval.whoIsAsking': 'Usaba ni:',
  'approval.codeLabel': 'Kode yo kugenzura',
  'approval.codeInstruction':
    'Reba neza ko iyi kode ari yo yerekanwa aho urimo kwinjira. Nitidahura, kanda «Anga».',
  'approval.noCode':
    'Uyu musaba ntiyatanze kode yo kugenzura. Nutamenya neza icyo ari cyo, ntukemeze.',
  'approval.scopesTitle': 'Ibyo asaba kumenya',
  'approval.assuranceLabel': 'Urwego rusabwa',
  'approval.expiresIn': 'Bisigaje amasegonda {seconds}',
  'approval.expired': 'Igihe cyararangiye. Saba ko bongera kubyohereza.',
  'approval.approve': 'Emeza',
  'approval.deny': 'Anga',
  'approval.approveHint': 'Uzasabwa isura cyangwa igikumwe cyawe.',
  'approval.notMeTitle': 'Si jye wabisabye',
  'approval.notMeBody':
    'Niba utasabye kwinjira, kanda hano: tuzabyanga ako kanya kandi tubimenyeshe abashinzwe umutekano.',
  'approval.notMeConfirm': 'Yego, si jye wabisabye',
  'approval.multiplePending': 'Hari ibisabwa {count} bitegereje. Genzura buri kimwe ukwacyo.',
  'approval.approved': 'Wemeje.',
  'approval.denied': 'Wabyanze.',
  'approval.reported': 'Twabimenyeshejwe. Urakoze.',
  'approval.screenRecordingWarning':
    'Hari ikintu kirimo kwandika cyangwa gutwikira ecran yawe. Ntukemeze kugeza ubihagaritse.',

  // ── Plain-language scopes (04 §3 — localised on the device, never trusted
  //    from the wire; the broker's English scopeDescriptions are a fallback) ─
  'scope.openid': 'Kwemeza ko ari wowe',
  'scope.profile': 'Kumenya amazina yawe n’itariki y’amavuko',
  'scope.address': 'Kumenya aho utuye',

  // ── Devices (03 §4, 03 §5) ────────────────────────────────────────────────
  'devices.title': 'Ibikoresho byanjye',
  'devices.thisDevice': 'Iyi telefone',
  'devices.enrolledOn': 'Cyiyandikishije: {date}',
  'devices.lastUsed': 'Cyakoreshejwe bwa nyuma: {date}',
  'devices.neverUsed': 'Ntikirakoreshwa',
  'devices.status.pending': 'Kitegereje',
  'devices.status.active': 'Kirakora',
  'devices.status.revoked': 'Cyarahagaritswe',
  'devices.revoke': 'Hagarika iki gikoresho',
  'devices.revokeConfirmTitle': 'Guhagarika {label}?',
  'devices.revokeConfirmBody':
    'Iki gikoresho ntikizongera kwemeza kwinjira. Ibi ntibisubirwaho.',
  'devices.revoked': 'Igikoresho cyarahagaritswe.',
  'devices.addNew': 'Ongeraho telefone nshya',
  'devices.addNewBody':
    'Telefone nshya igomba kwiyandikisha yonyine, igenzurwe n’isura yawe. Urufunguzo ntirushobora kwimurwa ruva kuri iyi telefone.',

  // ── Activity log (07 §4 — citizen view of the audit trail) ────────────────
  'activity.title': 'Ibyakozwe',
  'activity.empty': 'Nta kintu kirakorwa.',
  'activity.action.enrolled': 'Kwiyandikisha kw’igikoresho',
  'activity.action.login': 'Kwinjira',
  'activity.action.approved': 'Kwemeza kwinjira',
  'activity.action.denied': 'Kwanga kwinjira',
  'activity.action.revoked': 'Guhagarika igikoresho',
  'activity.action.consentGranted': 'Gutanga uruhushya',
  'activity.action.consentRevoked': 'Gukuraho uruhushya',
  'activity.action.other': 'Ikindi',
  'activity.result.success': 'Byagenze neza',
  'activity.result.failure': 'Byanze',
  'activity.result.denied': 'Byanzwe',

  // ── Consents (04 §5, 08 §5) ───────────────────────────────────────────────
  'consents.title': 'Uruhushya natanze',
  'consents.empty': 'Nta ruhushya urahaba serivisi.',
  'consents.grantedOn': 'Rwatanzwe: {date}',
  'consents.revoke': 'Kuraho uruhushya',
  'consents.revokeConfirm': 'Gukuraho uruhushya wahaye {name}?',
  'consents.revoked': 'Uruhushya rwakuweho.',

  // ── Settings ──────────────────────────────────────────────────────────────
  'settings.title': 'Igenamiterere',
  'settings.language': 'Ururimi',
  'settings.about': 'Ibyerekeye porogaramu',
  'settings.version': 'Verisiyo {version}',
  'settings.help': 'Ubufasha',
  'settings.privacy': 'Uko amakuru yawe arindwa',
  'settings.reportProblem': 'Menyesha ikibazo',

  // ── Errors: broker error codes (packages/shared/src/errors.ts) ────────────
  // One key per ErrorCode. Deliberately vague about the cause (03 §7).
  'errors.invalid_request': 'Ubusabe ntibwakiriwe. Ongera ugerageze.',
  'errors.enrolment_failed':
    'Ntibishobotse kwemeza umwirondoro wawe. Ongera ugerageze, cyangwa usabe ubufasha ku biro bikwegereye.',
  'errors.attestation_rejected':
    'Ntibishoboka gukoresha iyi telefone kubera impamvu z’umutekano. Gerageza indi telefone itigeze ihindurwa.',
  'errors.attestation_unavailable':
    'Ntitwabashije kugenzura umutekano w’iyi telefone ubu. Ongera ugerageze nyuma y’akanya.',
  'errors.binding_not_found': 'Iyi telefone ntiyanditse. Banza wiyandikishe.',
  'errors.binding_not_active':
    'Iyi telefone yarahagaritswe. Iyandikishe bushya kugira ngo wongere kuyikoresha.',
  'errors.challenge_invalid': 'Igihe cyararangiye. Ongera ugerageze.',
  'errors.signature_invalid':
    'Ntitwabashije kwemeza urufunguzo rw’iyi telefone. Ongera ugerageze.',
  'errors.assurance_insufficient':
    'Iyi serivisi isaba urwego rw’ubwizerwe ruri hejuru y’urw’iyi telefone.',
  'errors.rate_limited': 'Wagerageje kenshi cyane. Tegereza akanya hanyuma wongere.',
  'errors.locked_out':
    'Byahagaritswe by’agateganyo kubera kugerageza kenshi. Tegereza hanyuma wongere.',
  'errors.unauthorized_client': 'Serivisi isaba ntiyemewe.',
  'errors.access_denied': 'Ntabwo wemerewe gukora ibi.',
  'errors.authorization_pending': 'Biracyategerejwe.',
  'errors.expired_token': 'Igihe cyararangiye. Ongera winjire.',
  'errors.slow_down': 'Tegereza gato hanyuma wongere.',
  'errors.invalid_grant': 'Ubu busabe ntibukiri bwemewe. Ongera ugerageze.',
  'errors.invalid_client': 'Serivisi isaba ntiyemewe.',
  'errors.invalid_scope': 'Ibyo serivisi isaba ntibyemewe.',
  'errors.unknown_user_id': 'Ntitwabonye uwo muntu.',
  'errors.sdid_unavailable':
    'Serivisi y’indangamuntu ntiraboneka ubu. Ongera ugerageze nyuma y’akanya.',
  'errors.internal_error': 'Habaye ikibazo. Ongera ugerageze nyuma y’akanya.',

  // ── Errors: device-local (never reach the broker) ─────────────────────────
  'errors.network_unreachable': 'Nta murandasi uhari. Reba ko internet ikora.',
  'errors.network_timeout': 'Igisubizo cyatinze. Reba internet yawe hanyuma wongere.',
  'errors.server_unreachable':
    'Ntitwabashije kugera kuri serivisi. Ongera ugerageze nyuma y’akanya.',
  'errors.unexpected_response': 'Igisubizo ntikizwi. Ongera ugerageze.',
  'errors.biometric_unavailable': 'Isura n’igikumwe ntibikora kuri iyi telefone.',
  'errors.biometric_not_enrolled':
    'Banza ushyireho isura cyangwa igikumwe mu igenamiterere rya telefone yawe.',
  'errors.biometric_cancelled': 'Wahagaritse kwemeza.',
  'errors.biometric_failed': 'Ntitwabashije kukumenya. Ongera ugerageze.',
  'errors.secure_hardware_unavailable':
    'Iyi telefone ntifite ubwihisho bw’umutekano bukenewe.',
  'errors.keystore_failed':
    'Ntibishobotse gukoresha urufunguzo rw’umutekano rw’iyi telefone.',
  'errors.attestation_failed_local': 'Ntibishobotse kugenzura umutekano w’iyi telefone.',
  'errors.not_enrolled': 'Banza wiyandikishe kuri iyi telefone.',
  'errors.interrupted':
    'Ubusabe bwacitse mu nzira. Tangira bushya kugira ngo umutekano ukomeze.',
  'errors.unknown': 'Habaye ikibazo kitazwi. Ongera ugerageze.',
} as const;
