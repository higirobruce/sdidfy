package com.sdid.authenticator.keystore

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

/**
 * Registers `SdidKeyStore` with the bridge. See ../android/README.md for how
 * this gets added to `MainApplication`'s package list — that file doesn't
 * exist yet either, since `android/` hasn't been generated in this repo.
 */
class SdidKeyStorePackage : ReactPackage {
  override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
    listOf(SdidKeyStoreModule(reactContext))

  override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> =
    emptyList()
}
