# BL4 Auto Crypter
[![Modding Support Discord](https://img.shields.io/static/v1?label=&message=Modding%20Support%20Discord&logo=discord&color=424)](https://discord.gg/bXeqV8Ef9R)

Plugin to make sharing and editing BL4 saves as easy as in the previous games. Makes sure every save
always has a synced `.sav` and `.yaml` version, without ever needing to worry about your user id.

[Demo Video](https://youtu.be/WIUBeQwOpCg)

BL4 saves are stored in the following folder - everything this plugin does writes into it.
```
<my documents>\My Games\Borderlands 4\Saved\SaveGames\<user id>\Profiles\client\
```

## Installation
1. Make you you have a dll plugin loader. If you have the SDK installed (not released at time of
   writing), you already have this, and can skip this step.

   Otherwise, [download it from here][1] ([source code][2]), then take `dsound.dll`, and move it to
   `Borderlands 4\OakGame\Binaries\Win64`.

   If you're playing on Linux using Proton, you also need to add the following launch arg:
   ```
   WINEDLLOVERRIDES="dsound=n,b" %command%
   ```

   [1]: https://github.com/bl-sdk/pluginloader/releases/download/latest/msvc-x64-release.zip
   [2]: https://github.com/bl-sdk/pluginloader

2. Download the [latest release](https://github.com/apple1417/bl4_auto_crypter/releases/latest).

3. Extract the files into `Borderlands 4\OakGame\Binaries\Win64\Plugins`.

## How it works
Every time the game makes a new save, this plugin looks through all your saves and makes sure
they're synced. If the `.sav` has been modified, it decrypts it and updates the `.yaml`, and
conversely if the `.yaml` has been modified it encrypts it and updates the `.sav`. If both were
modified, the one with the newest write time wins, and if only one of the files exists it creates
the other.

Selecting a new character on the main menu triggers a new save (your profile stores the last
selected character), so is a convenient way to trigger a sync without restarting the game.

One word of warning: **THIS PLUGIN DOES NOT VALIDATE YOUR YAML**. If you give it an invalid yaml
file, it will happy encrypt it creating an invalid save file, overwriting whatever you had before.

### How to share a save file with others
The person creating the save:
1. Trigger a save anywhere in game as normal.
2. Upload the relevant `.yaml`. You can do so immediately.

The people downloading the save:
1. Download the `.yaml`, put it in your saves folder.
2. Get to the main menu.
3. If you were already on the main menu, select a different character to trigger a new sync.
4. Select character again, and you should have an option for the new character.

### How to save edit
1. Quit to main menu.
2. Edit your `.yaml` however you like.
3. Select a different character to trigger a new sync.
4. Select your original character again.

Note that some UI elements, e.g. player level, don't immediately update, but will once you go back
in game.

### Does it work with save editors that only support `.sav`s
Yes. A save editor updating the `.sav` is essentially the same thing as the game updating it. If you
both edit the `.sav` directly and the `.yaml`, the newest write time wins.

Though since the point of this plugin is to stop worrying about user ids and encryption/decryption,
I'd recommend finding a better editor which supports `.yaml` files directly.

### Does it work with cloud saves?
Mostly. Once again, the game downloading a cloud save is essentially the same thing as it saving it
normally.

The main edge case to watch out for is if you deleted a save on one PC, but still have it's `.yaml`
lying around on another. When the cloud update deletes the `.sav`, it will leave the `.yaml`, and
the plugin will re-create the `.sav` from it. In this case you can simply delete them again in game,
deleting from the menu will remove both.

Another potential issue is if you save edited with the game closed, a cloud update might overwrite
your changes - since newest write time wins. This has always been a risk in all games, best practice
is to do all save editing with game open.
