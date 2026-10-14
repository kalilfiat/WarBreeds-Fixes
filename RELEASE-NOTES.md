WarBreeds Fixes 1.0.0 is an unofficial, reversible patch for the verified Steam edition on Windows. Its installer lets you choose each improvement, including keeping the original gameplay aspect ratio.

Download **WarBreeds-Fixes-1.0.0-Public.zip**, extract the entire archive and run **WarBreeds-Fixes.exe** with the game closed. Select the game folder and your options. No Python is required.

Available options:

- Optional 1920×1080 gameplay.
- Corrected cursor and movement marker animation timing.
- Corrected holograms and decorative UI panels.
- Mouse wheel zoom using 960×540 / 1920×1080 internal resolutions; requires widescreen.
- Proportional cinematic enlargement, with the movie canvas detected at installation.
- DDrawCompat 0.7.0 and selectable CRT presets.
- Local QuickTime 2 playback repair. Missing components are acquired separately from the recorded source and verified by SHA256 before installation.

**Compatibility:** original `WARBREED.EXE` SHA256 must be `0e0768693a62ba89fcd5f1fd56dfcda68206d32bc6d5b5c285792996115061e3`. Other editions or already-modified executables are rejected. Restore previous standalone patches or use a clean installation first.

**Known behavior:** wheel zoom briefly blanks the screen while changing resolution and also enlarges the UI. Movies retain their original aspect ratio and therefore may show bars. The cinematic canvas is detected at installation up to 4096×4096; larger desktops use 1920×1080.

The original tester confirmed the fixes in game. Packaging checks passed on copies: 24 feature combinations, 344 emulated x86 hook cases, 44 injected write failures and native PE mapping for eight zoom variants. Broader hardware testing is welcome.

To uninstall, run the same installer and choose **Restaurar**. Preserve the `WarBreedsFixes` folder created inside the game; it contains installation-specific backups.

The public archive contains no original/patched game executable, movies, maps, saved games, personal backups or bundled QuickTime runtime. Executable changes are applied through binary differences. The attached **SHA256SUMS.txt** verifies the download.

GitHub's automatic **Source code** archives are for development; use the named Public ZIP for the installer. This project is not affiliated with Steam or the game publisher.
