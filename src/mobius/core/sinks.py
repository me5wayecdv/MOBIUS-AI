"""The sinks worth reaching, and the guards that count as protection.

This is a curated catalogue, not a rule database. Each entry states what it means in
evidence terms and is deliberately small: a large list of suspicious API names is how a
scanner generates volume, and volume is what MOBIUS exists to avoid.

The rule for membership: **a sink is an operation whose execution is itself security-relevant.**
Reading a value is not one. `SharedPreferences.getString` was in an early version of this
catalogue and produced a confirmed finding against a real APK whose exported receiver merely
read its own settings - a disclosure that does not happen. Reachability without data flow
cannot distinguish "reads a preference" from "returns that preference to the caller", so the
catalogue must not pretend it can. Same reasoning excludes `Context.startActivity`, whose
security relevance depends entirely on where the intent came from.

A sink is only ever half of a finding. "Reaches `FileOutputStream`" is not a vulnerability;
"reaches `FileOutputStream` from an exported entry point with no caller check and an
attacker-supplied path" is. The reachability engine supplies the first part; the gate decides
whether the rest is established.

Matching is by internal descriptor (`Ljava/io/FileOutputStream;`), because that is what a
dex reference contains. Names are matched exactly rather than by substring so that
`java/io/File` does not match `java/io/FileOutputStream`.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class Sink:
    """A sensitive API call, identified as a dex method reference."""

    id: str
    class_descriptor: str
    method: str
    family: str
    maswe: tuple[str, ...]
    description: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.class_descriptor, self.method)


@dataclass(frozen=True, slots=True)
class Guard:
    """A call that constitutes a caller check.

    Presence of a guard somewhere on a path does not automatically make the path safe - a
    guard can be bypassable - but its presence means *we cannot claim the check is absent*,
    which is exactly what the `caller_check_absent` clause asks. That distinction is why
    guards refute the clause rather than proving safety.
    """

    id: str
    class_descriptor: str
    method: str
    description: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.class_descriptor, self.method)


_SINKS: tuple[Sink, ...] = (
    Sink(
        id="file-write",
        class_descriptor="Ljava/io/FileOutputStream;",
        method="<init>",
        family="file-write",
        maswe=("MASWE-0001",),
        description="Writes a file in app storage from a path that may be externally influenced",
    ),
    Sink(
        id="file-append",
        class_descriptor="Ljava/io/FileWriter;",
        method="<init>",
        family="file-write",
        maswe=("MASWE-0001",),
        description="Writes text to a file path",
    ),
    Sink(
        id="file-read",
        class_descriptor="Ljava/io/FileInputStream;",
        method="<init>",
        family="file-read",
        maswe=("MASWE-0001",),
        description="Reads a file from a path that may be externally influenced",
    ),
    Sink(
        id="webview-load",
        class_descriptor="Landroid/webkit/WebView;",
        method="loadUrl",
        family="webview",
        maswe=("MASWE-0034",),
        description="Navigates a WebView to a URL that may be attacker-controlled",
    ),
    Sink(
        id="webview-js-interface",
        class_descriptor="Landroid/webkit/WebView;",
        method="addJavascriptInterface",
        family="webview",
        maswe=("MASWE-0034",),
        description="Exposes native objects to JavaScript running in the WebView",
    ),
    Sink(
        id="process-exec",
        class_descriptor="Ljava/lang/Runtime;",
        method="exec",
        family="exec",
        maswe=("MASWE-0039",),
        description="Executes a shell command constructed at runtime",
    ),
    Sink(
        id="process-builder",
        class_descriptor="Ljava/lang/ProcessBuilder;",
        method="start",
        family="exec",
        maswe=("MASWE-0039",),
        description="Starts an external process",
    ),
    Sink(
        id="dynamic-load",
        class_descriptor="Ldalvik/system/DexClassLoader;",
        method="<init>",
        family="dynamic-code",
        maswe=("MASWE-0035",),
        description="Loads code from a dex path that may be outside the APK",
    ),
    Sink(
        id="reflective-invoke",
        class_descriptor="Ljava/lang/reflect/Method;",
        method="invoke",
        family="dynamic-code",
        maswe=("MASWE-0035",),
        description="Invokes a method resolved by reflection",
    ),
    Sink(
        id="provider-open-file",
        class_descriptor="Landroid/os/ParcelFileDescriptor;",
        method="open",
        family="file-read",
        maswe=("MASWE-0005",),
        description="Opens a file descriptor, typically from a content provider URI",
    ),
    Sink(
        id="raw-sql",
        class_descriptor="Landroid/database/sqlite/SQLiteDatabase;",
        method="rawQuery",
        family="sql",
        maswe=("MASWE-0003",),
        description="Executes SQL assembled at runtime",
    ),
)

_GUARDS: tuple[Guard, ...] = (
    Guard(
        id="check-calling-permission",
        class_descriptor="Landroid/content/Context;",
        method="checkCallingPermission",
        description="Checks the caller's permission before proceeding",
    ),
    Guard(
        id="check-calling-or-self-permission",
        class_descriptor="Landroid/content/Context;",
        method="checkCallingOrSelfPermission",
        description="Checks the caller's or own permission",
    ),
    Guard(
        id="check-permission",
        class_descriptor="Landroid/content/Context;",
        method="checkPermission",
        description="Checks an arbitrary permission string",
    ),
    Guard(
        id="enforce-calling-permission",
        class_descriptor="Landroid/content/Context;",
        method="enforceCallingPermission",
        description="Throws unless the caller holds a permission",
    ),
    Guard(
        id="enforce-calling-or-self-permission",
        class_descriptor="Landroid/content/Context;",
        method="enforceCallingOrSelfPermission",
        description="Throws unless the caller or self holds a permission",
    ),
    Guard(
        id="calling-uid",
        class_descriptor="Landroid/os/Binder;",
        method="getCallingUid",
        description="Compares the calling UID against an expected value",
    ),
    Guard(
        id="calling-pid",
        class_descriptor="Landroid/os/Binder;",
        method="getCallingPid",
        description="Identifies the calling process",
    ),
    Guard(
        id="calling-package",
        class_descriptor="Landroid/app/ActivityManager;",
        method="getCallingPackage",
        description="Identifies the calling package",
    ),
    Guard(
        id="signature-check",
        class_descriptor="Landroid/content/pm/PackageManager;",
        method="checkSignatures",
        description="Compares signing certificates",
    ),
)

SINKS: Mapping[tuple[str, str], Sink] = MappingProxyType({s.key: s for s in _SINKS})
GUARDS: Mapping[tuple[str, str], Guard] = MappingProxyType({g.key: g for g in _GUARDS})

# Lifecycle and entry-point methods, mapped to the component kinds that expose them. A graph
# search starting anywhere else would be meaningless: reachability is only a claim about what
# an external caller can trigger.
ENTRY_POINTS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "activity": ("onCreate", "onStart", "onResume", "onNewIntent", "onActivityResult"),
        "service": ("onCreate", "onStartCommand", "onStart", "onBind", "handleMessage", "onHandleIntent"),
        "receiver": ("onReceive",),
        "provider": ("query", "insert", "update", "delete", "call", "openFile", "getType", "bulkInsert"),
    }
)


def sink_for(class_descriptor: str, method: str) -> Sink | None:
    return SINKS.get((class_descriptor, method))


def guard_for(class_descriptor: str, method: str) -> Guard | None:
    return GUARDS.get((class_descriptor, method))


def entry_methods_for(kind: str) -> tuple[str, ...]:
    return ENTRY_POINTS.get(kind, ())
