===================================
Project Mu MM Supervisor Repository
===================================

============================= ================= =============== ===================
 Host Type & Toolchain        Build Status      Test Status     Code Coverage
============================= ================= =============== ===================
Windows_VS_                   |WindowsCiBuild|  |WindowsCiTest| |WindowsCiCoverage|
Ubuntu_GCC5_                  |UbuntuCiBuild|   |UbuntuCiTest|  |UbuntuCiCoverage|
============================= ================= =============== ===================

This repository is part of Project Mu.  Please see Project Mu for details https://microsoft.github.io/mu

This MM Supervisor feature repo contains the supervisor module under Standalone MM environment for X64 architecture,
refactored from TianoCore common modules and public portion of AMD SMM supervisor module. The repo intends to support
operating Standalone MM modules in a secure manner. Other peripheral libraries are also included to accomodate user
module operations.

Detailed Information
====================

It is suggested to start with `Microsoft MM Supervisor and SMM Enhanced Attestation (SEA) Overview <Docs/Overview.md>`_

Other key documents:

* `Traditional and Standalone MM Overview <Docs/TraditionalAndStandaloneMm.md>`_
* `MM Supervisor Design <Docs/MmSupervisorDesign.md>`_
* `MM Supervisor Developer Considerations <Docs/MmSupervisorDeveloperConsiderations.md>`_

* MM Supervisor Platform Integration

   * `MM Supervisor Software Component Overview <MmSupervisorPkg/Docs/PlatformIntegration/SoftwareComponentOverview.md>`_
   * `MM Supervisor Platform Integration Steps <MmSupervisorPkg/Docs/PlatformIntegration/PlatformIntegrationSteps.md>`_
   * `Using a Deny-by-Default MM Supervisor Policy <MmSupervisorPkg/Docs/PlatformIntegration/SwitchingToDenyByDefault.md>`_

Repository Philosophy
=====================

Like other Project MU feature repositories, the Project MU MM Supervisor feature repo does not strictly follow the
EDKII releases, but instead has a continuous main branch which will periodically receive cherry-picks of needed changes
from EDKII. For stable builds, release tags will be used instead to determine commit hashes at stable points in development.
Release branches may be created as needed to facilitate a specific release with needed features, but this should be avoided.

Consuming the MM Supervisor Feature Package
===========================================

Since this project does not follow the release fork model, the code should be
consumed from a release hash and should be consumed as a extdep in the platform
repo. To include, create a file named feature_mm_supv_ext_dep.yaml desired release
tag hash. This could be in the root of the project or in a subdirectory as
desired.

    {
      "scope": "global",

      "type": "git",

      "name": "FEATURE_MM_SUPV",

      "var_name": "FEATURE_MM_SUPV_PATH",

      "source": "https://github.com/microsoft/mu_feature_mm_supv.git",

      "version": "<RELEASE HASH>",

      "flags": ["set_build_var"]
    }

Setting the the var_name and the set_build_var flags will allow the build scripts
to reference the extdep location. To make sure that the package is discoverable
for the build, the following line should also be added to the build
MM supervisor GetPackagesPath list.

    shell_environment.GetBuildVars().GetValue("FEATURE_MM_SUPV_PATH", "")

*Note: If using pytool extensions older then version 0.17.0 you will need to
append the root path to the build variable string.*

After this the package should be discoverable to can be used in the build like
any other dependency.

Code of Conduct
===============

This project has adopted the Microsoft Open Source Code of Conduct https://opensource.microsoft.com/codeofconduct/

For more information see the Code of Conduct FAQ https://opensource.microsoft.com/codeofconduct/faq/
or contact `opencode@microsoft.com <mailto:opencode@microsoft.com>`_. with any additional questions or comments.

Contributions
=============

Contributions are always welcome and encouraged!
Please open any issues in the Project Mu GitHub tracker and read https://microsoft.github.io/mu/How/contributing/

* [Code Requirements](https://microsoft.github.io/mu/CodeDevelopment/requirements/)
* [Doc Requirements](https://microsoft.github.io/mu/DeveloperDocs/requirements/)

Issues
======

Please open any issues in the Project Mu GitHub tracker. [More
Details](https://microsoft.github.io/mu/How/contributing/)

Builds
======

Please follow the steps in the Project Mu docs to build for CI and local
testing. [More Details](https://microsoft.github.io/mu/CodeDevelopment/compile/)

Copyright & License
===================

Files in this repository have their own copyright. Otherwise, the following copyrights
applies.

| Copyright (C) Microsoft Corporation
| SPDX-License-Identifier: BSD-2-Clause-Patent

Upstream License (TianoCore)
===================

Copyright (c) 2019, TianoCore and contributors.  All rights reserved.

SPDX-License-Identifier: BSD-2-Clause-Patent

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

Subject to the terms and conditions of this license, each copyright holder
and contributor hereby grants to those receiving rights under this license
a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
(except for failure to satisfy the conditions of this license) patent
license to make, have made, use, offer to sell, sell, import, and otherwise
transfer this software, where such license applies only to those patent
claims, already acquired or hereafter acquired, licensable by such copyright
holder or contributor that are necessarily infringed by:

(a) their Contribution(s) (the licensed copyrights of copyright holders and
    non-copyrightable additions of contributors, in source or binary form)
    alone; or

(b) combination of their Contribution(s) with the work of authorship to
    which such Contribution(s) was added by such copyright holder or
    contributor, if, at the time the Contribution is added, such addition
    causes such combination to be necessarily infringed. The patent license
    shall not apply to any other combinations which include the
    Contribution.

Except as expressly stated above, no rights or licenses from any copyright
holder or contributor is granted under this license, whether expressly, by
implication, estoppel or otherwise.

DISCLAIMER

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

.. ===================================================================
.. This is a bunch of directives to make the README file more readable
.. ===================================================================

.. CoreCI

.. _Windows_VS: https://dev.azure.com/projectmu/mu/_build/latest?definitionId=111&&branchName=main
.. |WindowsCiBuild| image:: https://dev.azure.com/projectmu/mu/_apis/build/status/CI/Feature%20MM%20Supervisor/Mu%20Feature%20MM%20Supervisor%20-%20CI%20-%20GCC5?repoName=microsoft%2Fmu_feature_mm_supv&branchName=main
.. |WindowsCiTest| image:: https://img.shields.io/azure-devops/tests/projectmu/mu/111.svg
.. |WindowsCiCoverage| image:: https://img.shields.io/badge/coverage-coming_soon-blue

.. _Ubuntu_GCC5: https://dev.azure.com/projectmu/mu/_build/latest?definitionId=110&branchName=main
.. |UbuntuCiBuild| image:: https://dev.azure.com/projectmu/mu/_apis/build/status/CI/Feature%20MM%20Supervisor/Mu%20Feature%20MM%20Supervisor%20-%20CI%20-%20Windows%20VS?repoName=microsoft%2Fmu_feature_mm_supv&branchName=main
.. |UbuntuCiTest| image:: https://img.shields.io/azure-devops/tests/projectmu/mu/110.svg
.. |UbuntuCiCoverage| image:: https://img.shields.io/badge/coverage-coming_soon-blue
