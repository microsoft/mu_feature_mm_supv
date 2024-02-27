@setlocal
@set ToolName=%~n0%
@%PYTHON_COMMAND% %WORKSPACE%/SpamPkg/Plugins/TestPlugin/GenAux.py %*
