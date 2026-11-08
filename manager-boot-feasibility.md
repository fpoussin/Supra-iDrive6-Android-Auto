# Independent manager boot feasibility (superseded)

The current direction is an updater in the iDrive plugin, which updates only
the daemon and uses SSH recovery if the plugin cannot load. An independent
boot service is not required for that design. The investigation below records
the limitation of the earlier independent-manager proposal.

The lifecycle and recovery manager needs to start independently of the Android
Auto iDrive plugin. This has not been verified on the target head unit, so no
boot configuration has been changed and the manager must not be installed yet.

## Evidence

- The existing `NbtAad` plugin starts `nbt-aad` after the HMI loads the plugin.
  Its autostart flag and boot-loop guard therefore do not start anything if the
  plugin cannot load. See `milestone-7/rhmiapp/nbt_aad_app.cpp`.
- A published NBT Evo boot analysis identifies a QNX service starter using
  `/opt/sys/etc/starter.cfg` and additional domain configuration files:
  <https://www.hakstuff.net/blog/dissecting-the-bmw-nbt-hu-evo-infotainment-unit-boot-process>.
  This is evidence of a candidate integration point, not proof that it is
  suitable for this car.
- An existing SSH unlock project modifies `starter.cfg` and warns that files
  differ between software families and that a mismatched file can prevent
  booting: <https://github.com/Xayanix/nbt-evo-ssh-unlocker>.
- The separate QNX development VM and BeagleBone kit do not reproduce the
  head unit's service starter, flash layout or HMI startup.

## Required investigation on the head unit

Using the established SSH/ENET access, collect a read-only copy of the active
`/opt/sys/etc/starter.cfg` and the domain configuration files it references,
along with the software version and the relevant starter process command line.
Check for an existing supported, independently started extension point, its
dependencies, permissions, restart behavior and interaction with network and
filesystem initialization. Inspect configuration files for device-specific
credentials or identifiers before sharing them.

Before adopting any boot integration, establish a reversible, version-specific
installation and recovery procedure and verify on the car that the manager
starts after a cold boot while the plugin and daemon are unavailable. Verify
that Wi-Fi, the firewall and authentication allow recovery in that state.
Keep SSH recovery available throughout testing. Until these checks succeed,
the proposed independent boot and wireless recovery behavior is unverified.
