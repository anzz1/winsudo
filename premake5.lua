workspace "winsudo"
  configurations { "Release" }
  platforms { "Win32", "x64" }
  location "build"
  objdir ("build/obj")
  buildlog ("build/log/%{prj.name}.log")

  characterset ("MBCS")
  staticruntime "Off"
  exceptionhandling "Off"
  floatingpoint "Fast"
  floatingpointexceptions "Off"
  intrinsics "On"
  rtti "Off"
  omitframepointer "On"
  flags { "NoBufferSecurityCheck", "NoIncrementalLink", "NoManifest", "NoPCH", "NoRuntimeChecks", "OmitDefaultLibrary" }
  buildoptions { "/kernel", "/Gs1000000" }
  linkoptions { "/kernel", "/SAFESEH:NO", "/GUARD:NO", "/EMITPOGOPHASEINFO", "/RELEASE", "/DEBUG:NONE", "/DYNAMICBASE:NO", "/FIXED" }

  filter "configurations:Release"
    runtime "Release"
    defines "NDEBUG"
    optimize "Speed"
    symbols "Off"

  filter "platforms:Win32"
    architecture "x86"
    targetdir "bin/Win32"

  filter "platforms:x64"
    architecture "x64"
    targetdir "bin/x64"

project "winsudo"
  kind "ConsoleApp"
  language "C"
  targetextension ".exe"
  files { "src/winsudo.c", "src/version.h" }
  entrypoint "main"
  targetname "sudo"

if _ACTION and _ACTION >= "vs2010" then
  require "vstudio"
  premake.override(premake.vstudio.vc2010.elements, "clCompile", function(base, prj)
    local calls = base(prj)
    table.insert(calls, function() premake.vstudio.vc2010.element("SDLCheck", nil, "false") end)
    table.insert(calls, function() premake.vstudio.vc2010.element("ControlFlowGuard", nil, "false") end)
    table.insert(calls, function() premake.vstudio.vc2010.element("GuardEHContMetadata", nil, "false") end)
    return calls
  end)
  premake.override(premake.vstudio.vc2010.elements, "link", function(base, prj)
    local calls = base(prj)
    table.insert(calls, function() premake.vstudio.vc2010.element("RandomizedBaseAddress", nil, "false") end)
    table.insert(calls, function() premake.vstudio.vc2010.element("FixedBaseAddress", nil, "true") end)
    table.insert(calls, function() premake.vstudio.vc2010.element("SetChecksum", nil, "true") end)
    table.insert(calls, function() premake.vstudio.vc2010.element("LinkErrorReporting", nil, "NoErrorReport") end)
    table.insert(calls, function() premake.vstudio.vc2010.element("CETCompat", nil, "false") end)
    table.insert(calls, function() premake.vstudio.vc2010.element("ImageHasSafeExceptionHandlers", nil, "false") end)
    return calls
  end)
end
