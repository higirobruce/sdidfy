import type { Messages } from './types.js';

/**
 * English (05 §7). Typed as `Messages`, so this file stops compiling the
 * moment `rw.ts` gains a key it does not have.
 */
export const en: Messages = {
  'common.appName': 'SDID',
  'common.continue': 'Continue',
  'common.cancel': 'Cancel',
  'common.back': 'Back',
  'common.retry': 'Try again',
  'common.close': 'Close',
  'common.done': 'Done',
  'common.loading': 'Working...',
  'common.yes': 'Yes',
  'common.no': 'No',
  'common.help': 'Help',
  'common.errorTitle': 'Something went wrong',

  'language.title': 'Choose your language',
  'language.rw': 'Kinyarwanda',
  'language.en': 'English',
  'language.fr': 'French',

  'onboarding.welcomeTitle': 'Welcome',
  'onboarding.welcomeBody':
    'This app lets you sign in to government services with your face or fingerprint — no password.',
  'onboarding.start': 'Start registration',

  'enrol.nid.title': 'Enter your national ID number',
  'enrol.nid.label': 'National ID number',
  'enrol.nid.help': 'The number has 16 digits.',
  'enrol.nid.invalid': 'The national ID number must have 16 digits.',
  'enrol.nid.privacyNote':
    'Your ID number is not kept on this phone. It is used once, to confirm it is you.',

  'enrol.consent.title': 'Permission to check your identity',
  'enrol.consent.body':
    'Before this phone can sign you in to government services, we must confirm that it is really you.',
  'enrol.consent.point.match': 'Your face is compared with the one held by NIDA, once only.',
  'enrol.consent.point.noStore':
    'The photo of your face is not kept: it is deleted immediately after the comparison.',
  'enrol.consent.point.deviceKey':
    'This phone gets a secret key that can never leave it, unlocked only by your face or fingerprint.',
  'enrol.consent.point.revoke': 'You can stop this phone at any time.',
  'enrol.consent.agree': 'I agree, continue',
  'enrol.consent.decline': 'I do not agree',

  'enrol.capture.title': 'Take a photo of your face',
  'enrol.capture.instruction': 'Put your face in the circle, look at the camera, and blink once.',
  'enrol.capture.liveness': 'We are checking it is really you, not a photo.',
  'enrol.capture.capturing': 'Capturing...',
  'enrol.capture.retake': 'Take the photo again',

  'enrol.progress.attesting': 'Checking this phone’s security...',
  'enrol.progress.generatingKey': 'Creating the security key...',
  'enrol.progress.matching': 'Comparing your face with the record...',
  'enrol.progress.activating': 'Activating this phone...',

  'enrol.done.title': 'All set',
  'enrol.done.body':
    'This phone now confirms that it is you. You will not be asked for your ID number again.',
  'enrol.done.assurance': 'Assurance level: {level}',
  'enrol.failed.title': 'Registration could not be completed',
  'enrol.failed.body':
    'Please try again. If it keeps failing, ask for help at your nearest civil registry office.',

  'home.title': 'Home',
  'home.greeting': 'Hello, {name}',
  'home.deviceStatus.active': 'This phone is active',
  'home.deviceStatus.pending': 'This phone is waiting to be activated',
  'home.deviceStatus.revoked': 'This phone has been stopped',
  'home.assuranceLabel': 'Assurance level',
  'home.noPending': 'Nothing is waiting for your approval.',
  'home.pendingCount': '{count} request(s) waiting for your approval.',
  'home.recentActivity': 'Recent activity',
  'home.viewAll': 'View all',
  'home.devices': 'My devices',
  'home.settings': 'Settings',
  'home.lastUsed': 'Last used: {date}',

  'approval.title': 'Someone is asking to sign in as you',
  'approval.whoIsAsking': 'The request comes from:',
  'approval.codeLabel': 'Check code',
  'approval.codeInstruction':
    'Make sure this code is the same as the one shown where you are signing in. If it is different, press “Deny”.',
  'approval.noCode':
    'This request came without a check code. If you are not sure what it is, do not approve.',
  'approval.scopesTitle': 'What they are asking to know',
  'approval.assuranceLabel': 'Required level',
  'approval.expiresIn': '{seconds} seconds left',
  'approval.expired': 'Time has run out. Ask for the request to be sent again.',
  'approval.approve': 'Approve',
  'approval.deny': 'Deny',
  'approval.approveHint': 'You will be asked for your face or fingerprint.',
  'approval.notMeTitle': 'I did not request this',
  'approval.notMeBody':
    'If you did not ask to sign in, press here: we will deny it at once and report it to the security team.',
  'approval.notMeConfirm': 'Yes, I did not request this',
  'approval.multiplePending': '{count} requests are waiting. Check each one separately.',
  'approval.approved': 'Approved.',
  'approval.denied': 'Denied.',
  'approval.reported': 'Reported. Thank you.',
  'approval.screenRecordingWarning':
    'Something is recording or covering your screen. Do not approve until you stop it.',

  'scope.openid': 'Confirm that it is you',
  'scope.profile': 'See your name and date of birth',
  'scope.address': 'See where you live',

  'devices.title': 'My devices',
  'devices.thisDevice': 'This phone',
  'devices.enrolledOn': 'Registered: {date}',
  'devices.lastUsed': 'Last used: {date}',
  'devices.neverUsed': 'Never used',
  'devices.status.pending': 'Waiting',
  'devices.status.active': 'Active',
  'devices.status.revoked': 'Stopped',
  'devices.revoke': 'Stop this device',
  'devices.revokeConfirmTitle': 'Stop {label}?',
  'devices.revokeConfirmBody': 'This device will no longer approve sign-ins. This cannot be undone.',
  'devices.revoked': 'The device has been stopped.',
  'devices.addNew': 'Add a new phone',
  'devices.addNewBody':
    'A new phone must register on its own and be checked against your face. The key cannot be copied from this phone.',

  'activity.title': 'Activity',
  'activity.empty': 'Nothing has happened yet.',
  'activity.action.enrolled': 'Device registration',
  'activity.action.login': 'Sign-in',
  'activity.action.approved': 'Sign-in approved',
  'activity.action.denied': 'Sign-in denied',
  'activity.action.revoked': 'Device stopped',
  'activity.action.consentGranted': 'Permission given',
  'activity.action.consentRevoked': 'Permission withdrawn',
  'activity.action.other': 'Other',
  'activity.result.success': 'Succeeded',
  'activity.result.failure': 'Failed',
  'activity.result.denied': 'Denied',

  'consents.title': 'Permissions I have given',
  'consents.empty': 'You have not given any service a permission.',
  'consents.grantedOn': 'Given: {date}',
  'consents.revoke': 'Withdraw permission',
  'consents.revokeConfirm': 'Withdraw the permission you gave to {name}?',
  'consents.revoked': 'The permission has been withdrawn.',

  'settings.title': 'Settings',
  'settings.language': 'Language',
  'settings.about': 'About this app',
  'settings.version': 'Version {version}',
  'settings.help': 'Help',
  'settings.privacy': 'How your data is protected',
  'settings.reportProblem': 'Report a problem',

  'errors.invalid_request': 'The request was not accepted. Please try again.',
  'errors.enrolment_failed':
    'We could not confirm your identity. Please try again, or ask for help at your nearest office.',
  'errors.attestation_rejected':
    'This phone cannot be used for security reasons. Try a phone that has not been modified.',
  'errors.attestation_unavailable':
    'We could not check this phone’s security right now. Please try again shortly.',
  'errors.binding_not_found': 'This phone is not registered. Please register first.',
  'errors.binding_not_active':
    'This phone has been stopped. Register again to start using it.',
  'errors.challenge_invalid': 'Time has run out. Please try again.',
  'errors.signature_invalid': 'We could not verify this phone’s key. Please try again.',
  'errors.assurance_insufficient':
    'This service requires a higher assurance level than this phone has.',
  'errors.rate_limited': 'Too many attempts. Please wait a moment and try again.',
  'errors.locked_out':
    'Temporarily stopped after too many attempts. Please wait and try again.',
  'errors.unauthorized_client': 'The requesting service is not allowed.',
  'errors.access_denied': 'You are not allowed to do this.',
  'errors.authorization_pending': 'Still waiting.',
  'errors.expired_token': 'Time has run out. Please sign in again.',
  'errors.slow_down': 'Please wait a moment and try again.',
  'errors.invalid_grant': 'This request is no longer valid. Please try again.',
  'errors.invalid_client': 'The requesting service is not allowed.',
  'errors.invalid_scope': 'What the service is asking for is not allowed.',
  'errors.unknown_user_id': 'We could not find that person.',
  'errors.sdid_unavailable':
    'The identity service is not available right now. Please try again shortly.',
  'errors.internal_error': 'Something went wrong. Please try again shortly.',

  'errors.network_unreachable': 'No internet. Check that your connection is working.',
  'errors.network_timeout': 'The reply took too long. Check your connection and try again.',
  'errors.server_unreachable': 'We could not reach the service. Please try again shortly.',
  'errors.unexpected_response': 'The reply was not understood. Please try again.',
  'errors.biometric_unavailable': 'Face and fingerprint do not work on this phone.',
  'errors.biometric_not_enrolled':
    'First set up a face or fingerprint in your phone’s settings.',
  'errors.biometric_cancelled': 'You cancelled the approval.',
  'errors.biometric_failed': 'We could not recognise you. Please try again.',
  'errors.secure_hardware_unavailable': 'This phone does not have the required secure hardware.',
  'errors.keystore_failed': 'This phone’s security key could not be used.',
  'errors.attestation_failed_local': 'This phone’s security could not be checked.',
  'errors.not_enrolled': 'Please register on this phone first.',
  'errors.interrupted': 'The request was interrupted. Start again so security is preserved.',
  'errors.unknown': 'An unknown problem occurred. Please try again.',
};
