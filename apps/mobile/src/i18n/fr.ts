import type { Messages } from './types.js';

/**
 * French (05 §7). Typed as `Messages` — compile-checked for completeness
 * against the Kinyarwanda key set.
 */
export const fr: Messages = {
  'common.appName': 'SDID',
  'common.continue': 'Continuer',
  'common.cancel': 'Annuler',
  'common.back': 'Retour',
  'common.retry': 'Réessayer',
  'common.close': 'Fermer',
  'common.done': 'Terminé',
  'common.loading': 'Traitement en cours...',
  'common.yes': 'Oui',
  'common.no': 'Non',
  'common.help': 'Aide',
  'common.errorTitle': 'Un problème est survenu',

  'language.title': 'Choisissez votre langue',
  'language.rw': 'Kinyarwanda',
  'language.en': 'Anglais',
  'language.fr': 'Français',

  'onboarding.welcomeTitle': 'Bienvenue',
  'onboarding.welcomeBody':
    'Cette application vous permet d’accéder aux services publics avec votre visage ou votre empreinte — sans mot de passe.',
  'onboarding.start': 'Commencer l’inscription',

  'enrol.nid.title': 'Saisissez votre numéro de carte d’identité',
  'enrol.nid.label': 'Numéro de carte d’identité',
  'enrol.nid.help': 'Le numéro comporte 16 chiffres.',
  'enrol.nid.invalid': 'Le numéro de carte d’identité doit comporter 16 chiffres.',
  'enrol.nid.privacyNote':
    'Votre numéro n’est pas conservé sur ce téléphone. Il sert une seule fois, pour confirmer que c’est bien vous.',

  'enrol.consent.title': 'Autorisation de vérifier votre identité',
  'enrol.consent.body':
    'Avant que ce téléphone puisse vous connecter aux services publics, nous devons confirmer que c’est bien vous.',
  'enrol.consent.point.match': 'Votre visage est comparé une seule fois à celui détenu par la NIDA.',
  'enrol.consent.point.noStore':
    'La photo de votre visage n’est pas conservée : elle est supprimée aussitôt après la comparaison.',
  'enrol.consent.point.deviceKey':
    'Ce téléphone reçoit une clé secrète qui ne peut jamais en sortir, déverrouillée uniquement par votre visage ou votre empreinte.',
  'enrol.consent.point.revoke': 'Vous pouvez arrêter ce téléphone à tout moment.',
  'enrol.consent.agree': 'J’accepte, continuer',
  'enrol.consent.decline': 'Je refuse',

  'enrol.capture.title': 'Prenez une photo de votre visage',
  'enrol.capture.instruction':
    'Placez votre visage dans le cercle, regardez la caméra et clignez des yeux une fois.',
  'enrol.capture.liveness': 'Nous vérifions que c’est bien vous, et non une photo.',
  'enrol.capture.capturing': 'Capture en cours...',
  'enrol.capture.retake': 'Reprendre la photo',

  'enrol.progress.attesting': 'Vérification de la sécurité de ce téléphone...',
  'enrol.progress.generatingKey': 'Création de la clé de sécurité...',
  'enrol.progress.matching': 'Comparaison de votre visage avec l’enregistrement...',
  'enrol.progress.activating': 'Activation de ce téléphone...',

  'enrol.done.title': 'C’est fait',
  'enrol.done.body':
    'Ce téléphone confirme désormais que c’est vous. Votre numéro d’identité ne vous sera plus demandé.',
  'enrol.done.assurance': 'Niveau de garantie : {level}',
  'enrol.failed.title': 'L’inscription n’a pas pu aboutir',
  'enrol.failed.body':
    'Veuillez réessayer. Si le problème persiste, demandez de l’aide au bureau d’état civil le plus proche.',

  'home.title': 'Accueil',
  'home.greeting': 'Bonjour, {name}',
  'home.deviceStatus.active': 'Ce téléphone est actif',
  'home.deviceStatus.pending': 'Ce téléphone attend son activation',
  'home.deviceStatus.revoked': 'Ce téléphone a été arrêté',
  'home.assuranceLabel': 'Niveau de garantie',
  'home.noPending': 'Aucune demande n’attend votre approbation.',
  'home.pendingCount': '{count} demande(s) attendent votre approbation.',
  'home.recentActivity': 'Activité récente',
  'home.viewAll': 'Tout afficher',
  'home.devices': 'Mes appareils',
  'home.settings': 'Paramètres',
  'home.lastUsed': 'Dernière utilisation : {date}',

  'approval.title': 'Quelqu’un demande à se connecter en votre nom',
  'approval.whoIsAsking': 'La demande vient de :',
  'approval.codeLabel': 'Code de vérification',
  'approval.codeInstruction':
    'Vérifiez que ce code est identique à celui affiché là où vous vous connectez. S’il est différent, appuyez sur « Refuser ».',
  'approval.noCode':
    'Cette demande est arrivée sans code de vérification. Si vous n’en êtes pas sûr, n’approuvez pas.',
  'approval.scopesTitle': 'Ce qu’ils demandent à savoir',
  'approval.assuranceLabel': 'Niveau exigé',
  'approval.expiresIn': 'Il reste {seconds} secondes',
  'approval.expired': 'Le délai est écoulé. Demandez que la demande soit renvoyée.',
  'approval.approve': 'Approuver',
  'approval.deny': 'Refuser',
  'approval.approveHint': 'Votre visage ou votre empreinte vous sera demandé.',
  'approval.notMeTitle': 'Ce n’est pas moi qui ai fait cette demande',
  'approval.notMeBody':
    'Si vous n’avez pas demandé à vous connecter, appuyez ici : nous refuserons immédiatement et le signalerons à l’équipe de sécurité.',
  'approval.notMeConfirm': 'Oui, ce n’est pas moi',
  'approval.multiplePending': '{count} demandes sont en attente. Vérifiez chacune séparément.',
  'approval.approved': 'Approuvé.',
  'approval.denied': 'Refusé.',
  'approval.reported': 'Signalé. Merci.',
  'approval.screenRecordingWarning':
    'Quelque chose enregistre ou recouvre votre écran. N’approuvez pas avant de l’avoir arrêté.',

  'scope.openid': 'Confirmer que c’est bien vous',
  'scope.profile': 'Voir votre nom et votre date de naissance',
  'scope.address': 'Voir votre lieu de résidence',

  'devices.title': 'Mes appareils',
  'devices.thisDevice': 'Ce téléphone',
  'devices.enrolledOn': 'Enregistré : {date}',
  'devices.lastUsed': 'Dernière utilisation : {date}',
  'devices.neverUsed': 'Jamais utilisé',
  'devices.status.pending': 'En attente',
  'devices.status.active': 'Actif',
  'devices.status.revoked': 'Arrêté',
  'devices.revoke': 'Arrêter cet appareil',
  'devices.revokeConfirmTitle': 'Arrêter {label} ?',
  'devices.revokeConfirmBody':
    'Cet appareil n’approuvera plus aucune connexion. Cette action est irréversible.',
  'devices.revoked': 'L’appareil a été arrêté.',
  'devices.addNew': 'Ajouter un nouveau téléphone',
  'devices.addNewBody':
    'Un nouveau téléphone doit s’enregistrer lui-même et être vérifié par votre visage. La clé ne peut pas être copiée depuis ce téléphone.',

  'activity.title': 'Activité',
  'activity.empty': 'Rien ne s’est encore produit.',
  'activity.action.enrolled': 'Enregistrement de l’appareil',
  'activity.action.login': 'Connexion',
  'activity.action.approved': 'Connexion approuvée',
  'activity.action.denied': 'Connexion refusée',
  'activity.action.revoked': 'Appareil arrêté',
  'activity.action.consentGranted': 'Autorisation accordée',
  'activity.action.consentRevoked': 'Autorisation retirée',
  'activity.action.other': 'Autre',
  'activity.result.success': 'Réussi',
  'activity.result.failure': 'Échec',
  'activity.result.denied': 'Refusé',

  'consents.title': 'Autorisations que j’ai accordées',
  'consents.empty': 'Vous n’avez accordé aucune autorisation à un service.',
  'consents.grantedOn': 'Accordée : {date}',
  'consents.revoke': 'Retirer l’autorisation',
  'consents.revokeConfirm': 'Retirer l’autorisation accordée à {name} ?',
  'consents.revoked': 'L’autorisation a été retirée.',

  'settings.title': 'Paramètres',
  'settings.language': 'Langue',
  'settings.about': 'À propos de l’application',
  'settings.version': 'Version {version}',
  'settings.help': 'Aide',
  'settings.privacy': 'Comment vos données sont protégées',
  'settings.reportProblem': 'Signaler un problème',

  'errors.invalid_request': 'La demande n’a pas été acceptée. Veuillez réessayer.',
  'errors.enrolment_failed':
    'Nous n’avons pas pu confirmer votre identité. Réessayez, ou demandez de l’aide au bureau le plus proche.',
  'errors.attestation_rejected':
    'Ce téléphone ne peut pas être utilisé pour des raisons de sécurité. Essayez un téléphone non modifié.',
  'errors.attestation_unavailable':
    'Nous n’avons pas pu vérifier la sécurité de ce téléphone pour le moment. Réessayez dans un instant.',
  'errors.binding_not_found': 'Ce téléphone n’est pas enregistré. Enregistrez-le d’abord.',
  'errors.binding_not_active':
    'Ce téléphone a été arrêté. Enregistrez-le à nouveau pour l’utiliser.',
  'errors.challenge_invalid': 'Le délai est écoulé. Veuillez réessayer.',
  'errors.signature_invalid':
    'Nous n’avons pas pu vérifier la clé de ce téléphone. Veuillez réessayer.',
  'errors.assurance_insufficient':
    'Ce service exige un niveau de garantie supérieur à celui de ce téléphone.',
  'errors.rate_limited': 'Trop de tentatives. Patientez un instant puis réessayez.',
  'errors.locked_out':
    'Arrêté temporairement après trop de tentatives. Patientez puis réessayez.',
  'errors.unauthorized_client': 'Le service demandeur n’est pas autorisé.',
  'errors.access_denied': 'Vous n’êtes pas autorisé à faire cela.',
  'errors.authorization_pending': 'En attente.',
  'errors.expired_token': 'Le délai est écoulé. Reconnectez-vous.',
  'errors.slow_down': 'Patientez un instant puis réessayez.',
  'errors.invalid_grant': 'Cette demande n’est plus valable. Veuillez réessayer.',
  'errors.invalid_client': 'Le service demandeur n’est pas autorisé.',
  'errors.invalid_scope': 'Ce que le service demande n’est pas autorisé.',
  'errors.unknown_user_id': 'Nous n’avons pas trouvé cette personne.',
  'errors.sdid_unavailable':
    'Le service d’identité n’est pas disponible pour le moment. Réessayez dans un instant.',
  'errors.internal_error': 'Un problème est survenu. Réessayez dans un instant.',

  'errors.network_unreachable': 'Pas d’internet. Vérifiez votre connexion.',
  'errors.network_timeout': 'La réponse a mis trop de temps. Vérifiez votre connexion et réessayez.',
  'errors.server_unreachable': 'Nous n’avons pas pu joindre le service. Réessayez dans un instant.',
  'errors.unexpected_response': 'La réponse n’a pas été comprise. Veuillez réessayer.',
  'errors.biometric_unavailable': 'Le visage et l’empreinte ne fonctionnent pas sur ce téléphone.',
  'errors.biometric_not_enrolled':
    'Configurez d’abord un visage ou une empreinte dans les paramètres de votre téléphone.',
  'errors.biometric_cancelled': 'Vous avez annulé l’approbation.',
  'errors.biometric_failed': 'Nous n’avons pas pu vous reconnaître. Veuillez réessayer.',
  'errors.secure_hardware_unavailable':
    'Ce téléphone ne dispose pas du matériel sécurisé requis.',
  'errors.keystore_failed': 'La clé de sécurité de ce téléphone n’a pas pu être utilisée.',
  'errors.attestation_failed_local': 'La sécurité de ce téléphone n’a pas pu être vérifiée.',
  'errors.not_enrolled': 'Enregistrez-vous d’abord sur ce téléphone.',
  'errors.interrupted':
    'La demande a été interrompue. Recommencez afin de préserver la sécurité.',
  'errors.unknown': 'Un problème inconnu est survenu. Veuillez réessayer.',
};
