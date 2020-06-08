#pragma once
#define ADDRESS_GAMEMANAGER 0x5306348
#define ADDRESS_ROUNDMANAGER 0x52f5bf8
#define ADDRESS_VTABLE 0x395ba68
#define ADDRESS_UNLOCKALL 0x1138490

#define OFFSET_UNLOCKALL_JNE 0x23c
#define OFFSET_UNLOCKALL_ENABLE 0x259

#define OFFSET_GAMEMANAGER_ENTITYLIST 0x1c8
#define OFFSET_ROUNDMANAGER_STATE 0x2e8
#define OFFSET_ENTITY_ENTITYINFO 0x28
#define OFFSET_ENTITYINFO_MAINCOMPONENT 0xd8
#define OFFSET_MAINCOMPONENT_ESPCHAIN 0x70
#define OFFSET_ESPCHAIN_SPOTTED 0x534

/*

-- Signatures --

gamemanager: 48 8b 05 ? ? ? ? 8b 8e
roundmanager: 48 8b 0d ? ? ? ? e8 ? ? ? ? 83 bb
vtable: 4c 8d 0d ? ? ? ? 48 ? ? ? 48 8d 8b ? ? ? ? 4c ? ? 48 8d ? ? ? ? ? e8
unlock all: E8 ? ? ? ? 48 85 F6 74 ? 48 8B CB E8 ? ? ? ? 48 8B 5C 24 ? 48 8B 6C 24 ? 48 83 C4 ? 41 5E 5F 5E C3
*/