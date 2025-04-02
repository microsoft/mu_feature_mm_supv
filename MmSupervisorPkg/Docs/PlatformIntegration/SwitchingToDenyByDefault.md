# Switching MSR and IO MmPolicy from allow by default to deny by default

Individual platform MmPolicy can be edited in the corresponding "YourPlatform"MmPolicy.xml with an example in
this repo at
[`MmSupervisorPkg/SupervisorPolicyTools/MmIsolationPoliciesExample.xml`](../../SupervisorPolicyTools/MmIsolationPoliciesExample.xml).
MSR and IO policy in this example uses a deny list to list ports that a platform cannot use.  This document describes
how to go about switching to an allow list instead.

## Transition process

1. Without changing any policies add the PCD `gMmSupervisorPkgTokenSpaceGuid.PcdMmSupervisorPrintPortsEnable` to your
   platform .dsc file and set it to true.  Adding `gMmSupervisorPkgTokenSpaceGuid.PcdMmSupervisorPrintPortsMaxSize` to
   FixedPcd allows you to change the max dictionary size if necessary and is 50 by default. This will print out all
   the MSR and IO ports currently being used in MM including their address and size which are required for making
  MM policies.

2. Switch to an allow list by switching the PolicyAccessAttribute to "Allow". Create the allow list by following the
   list structure in your corresponding .xml file (refer to MmIsolationPoliciesExample.xml) and the address and size
   information from step 1.

   Examples:

   - **Allow by default:**

   ```xml
      <!-- IO Policies required for level 20 start -->
      <SmmCategory name="IO">
          <!-- All IO policy entries listed here are allowed -->
          <PolicyAccessAttribute Value="Deny"/>

          <!-- This policy denies the IO at port 0xADAA read and write access -->
          <PolicyEntry>
              <!-- Junk address and port-->
              <StartAddress Value="0xADAA" /> <Size Value="0x2" /> <SecurityAttributes Value="Read | Write" />
          </PolicyEntry>
   ```

   - **Deny by default (recommended):**

   ```xml
      <!-- IO Policies required for level 20 start -->
      <SmmCategory name="IO">
          <!-- All IO policy entries listed here are allowed -->
          <PolicyAccessAttribute Value="Allow"/>

          <!-- This policy allows the IO at port 0xADAA to have read and write access -->
          <PolicyEntry>
              <!-- Junk address and port-->
              <StartAddress Value="0xADAA" /> <Size Value="0x2" /> <SecurityAttributes Value="Read | Write" />
          </PolicyEntry>
   ```

3. It is recommended to also look into each of the MSR and IO port addresses that you’re adding to the allow list and
   leave a describing comment about them. This can either be done by going through spec documentation describing the
   addresses and bits or by looking through the code itself and finding references to the addresses.

4. For posterity you should then look for additional MSR and IO ports that you might want to add to the allow list
   as well.

    A couple of ways to do this (with Intel system examples) would be:

    - Look for a file listing MSRs that you can audit. When doing step 3 you'll probably run across the file.
      An example for Intel systems is `CommonMsr.h`.

    - Look around the location of defined MSR and IO ports that you're currently allowing. There might be other
      relevant IO and MSR defintions that you’d want to have on the allow list that currently are not being used.

    - There might be an existing allow list for other MM platforms.  If so it's an excellent point of reference for
      relevant MSR and IO ports. An example from intel systems is `SmmIoMsrAccess.h`. An allow list for Intel SMM MSR
      and IO ports.

5. After compiling your list of MSR and IO ports make sure that you aren't violating the previous deny list requirements.
   Some of these ports that you thought are relevant might have been explicitly denied by the previous deny list. Make
   sure you don't put them on the allow list.

6. To finish things off make sure that things boot correctly for all supported scenarios and, if so, you're done.
