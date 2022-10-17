# Microsoft MM Supervisor

??? info "Git Details"
    Repository Url: {{mu_feature_mm_supv.url}}  
    Branch:         {{mu_feature_mm_supv.branch}}  
    Commit:         [{{mu_feature_mm_supv.commit}}]({{mu_feature_mm_supv.commitlink}})  
    Commit Date:    {{mu_feature_mm_supv.date}}

## Repository Philosophy

Like other Project MU feature repositories, the Project MU MM Supervisor feature repo does not strictly follow the
EDKII releases, but instead has a continuous main branch which will periodically receive cherry-picks of needed changes
from EDKII. For stable builds, release tags will be used instead to determine commit hashes at stable points in development.
Release branches may be created as needed to facilitate a specific release with needed features, but this should be avoided.

## Consuming the MM Supervisor Feature Package

Since this project does not follow the release fork model, the code should be
consumed from a release hash and should be consumed as a extdep in the platform
repo. To include, create a file named feature_mm_supv_ext_dep.yaml desired release
tag hash. This could be in the root of the project or in a subdirectory as
desired.

```yaml
{
  "scope": "global",
  "type": "git",
  "name": "FEATURE_MM_SUPV",
  "var_name": "FEATURE_MM_SUPV_PATH",
  "source": "https://github.com/microsoft/mu_feature_mm_supv.git",
  "version": "<RELEASE HASH>",
  "flags": ["set_build_var"]
}
```

Setting the the var_name and the set_build_var flags will allow the build scripts
to reference the extdep location. To make sure that the package is discoverable
for the build, the following line should also be added to the build
MM supervisor GetPackagesPath list.

```python
    shell_environment.GetBuildVars().GetValue("FEATURE_MM_SUPV_PATH", "")
```

*Note: If using pytool extensions older then version 0.17.0 you will need to
append the root path to the build variable string.*

After this the package should be discoverable to can be used in the build like
any other dependency.

## Code of Conduct

This project has adopted the Microsoft Open Source Code of Conduct https://opensource.microsoft.com/codeofconduct/

For more information see the Code of Conduct FAQ https://opensource.microsoft.com/codeofconduct/faq/
or contact `opencode@microsoft.com <mailto:opencode@microsoft.com>`_. with any additional questions or comments.

## Contributions

Contributions are always welcome and encouraged!
Please open any issues in the Project Mu GitHub tracker and read https://microsoft.github.io/mu/How/contributing/

* [Code Requirements](https://microsoft.github.io/mu/CodeDevelopment/requirements/)
* [Doc Requirements](https://microsoft.github.io/mu/DeveloperDocs/requirements/)

## Issues

Please open any issues in the Project Mu GitHub tracker. [More
Details](https://microsoft.github.io/mu/How/contributing/)


## Builds

Please follow the steps in the Project Mu docs to build for CI and local
testing. [More Details](https://microsoft.github.io/mu/CodeDevelopment/compile/)

## Copyright

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent
