# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Native entry points are looked up by the JNI bridge and are not visible to
# R8's Java call graph.
# Anything reachable from JNI must survive R8. The native side looks these up
# by name, so shrinking or renaming them fails only at runtime, on a device,
# in a release build — the worst possible place to find out.
-keepclasseswithmembernames,includedescriptorclasses class com.ccs.mint.core.** {
    native <methods>;
}

-keep class com.ccs.mint.core.NativeCore { *; }
-keep class com.ccs.mint.core.MintSession { *; }

