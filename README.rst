=================================
Exporting Non-Exportable RSA Keys
=================================

This project has been directly inspired by the follwing paper:

https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf

by Jason Geffner <jason.geffner@ngssecure.com> that can be found in the doc folder

The repo contains a Visual Studio 2022 buildable project. Build it yourself as
described in the `Building`_ section below; no prebuilt executables are
committed. The Release binary links the C runtime statically, so the resulting
exportrsa.exe is a single self-contained file.

How to use
~~~~~~~~~~

The code parse all system key stores and export in .pfx files all that have a RSA private key available.

Just run exportrsa.exe in a command shell::

    exportrsa.exe [-verbose] [--include-cng] [--include-expired]
                  [--no-password] [--password-file <path>] [--non-interactive]
                  [-h]

For every certificate it is about to export the tool prints the certificate
name together with the whole chain up to the root, showing for each link its
issue date, expiration date and the name of the issuing certificate. For a
self-signed (root) certificate, where the issuer is the certificate itself, the
issuer is shown as ``<self>``.

A single password protects every exported PFX file. By default it is collected
once at startup (with confirmation). It can instead be read from the first line
of a file with ``--password-file <path>``, or, in ``--non-interactive`` mode,
piped in on stdin. Use ``--no-password`` to export with an empty password. The
precedence is: ``--password-file`` > ``--no-password`` > stdin (non-interactive)
> interactive prompt.

For each candidate certificate the tool prints the chain and then asks whether
to export it. The default is Yes, so you can read the details and simply press
Enter to export; answer ``n`` to skip that one. Pass ``--non-interactive`` to
export everything without any prompting. CNG and expired certificates are
skipped by default without asking; when one is skipped the tool prints a line
saying so and naming the switch that would include it (``--include-cng`` /
``--include-expired``).

The same certificate often appears in more than one store (for example both the
current-user and local-machine stores). The tool tracks the SHA1 thumbprints it
has already exported and exports each certificate only once per run.

Each exported file is named with the certificate's issue date first, followed by
the issuer's name and the certificate's name, in a file-safe form
(e.g. ``2026-09-17_My_CA_www.example.com.pfx``) instead of ``1.pfx``. If two
certificates would map to the same file name a numeric suffix is added.

Switches
~~~~~~~~

``-verbose`` (also ``--verbose``)
    Print diagnostics about certificates that are skipped because they have no
    associated (RSA) private key. These messages are suppressed by default.

``--include-cng``
    Also export CNG (KeyIso) private keys. By default only CryptoAPI keys are
    exported and CNG keys are skipped (exporting them requires write access to
    the lsass.exe process, i.e. running as SYSTEM).

``--include-expired``
    Also export certificates that have already expired. By default expired
    certificates are skipped.

``--no-password``
    Do not prompt for a password; export the PFX files with an empty password.
    By default you are prompted (twice) for a password to protect each export.

``--password-file <path>`` (or ``--password-file=<path>``)
    Read the export password from the first line of ``<path>`` (a trailing
    CR/LF is stripped) instead of prompting. Takes precedence over the other
    password options.

``--non-interactive``
    Export every eligible certificate without prompting at all. The password is
    read from stdin (first line) unless ``--password-file`` or ``--no-password``
    is given; if nothing is piped in, the password is empty. Combine with
    ``--include-cng`` / ``--include-expired`` to dump those as well.

``-h`` (also ``--help`` or ``/?``)
    Print a short usage summary and exit without exporting anything.

Building
~~~~~~~~

Open ``exportrsa/exportrsa.sln`` in Visual Studio 2022 with the "Desktop
development with C++" workload (which supplies the v143 toolset) and a
Windows 10/11 SDK, then build the Release / Win32 configuration.

To build from a Developer Command Prompt for VS 2022 instead::

    msbuild exportrsa\exportrsa.sln /p:Configuration=Release /p:Platform=Win32

The project targets the v143 toolset and builds as a 32-bit (Win32) application.
Both configurations link the C runtime statically (``/MT`` for Release, ``/MTd``
for Debug), so the built exportrsa.exe runs on a clean Windows machine with no
Visual C++ redistributable installed. Copy the exe on its own to the target
machine; it needs no accompanying runtime DLLs.
