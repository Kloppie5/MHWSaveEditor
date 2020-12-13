using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MHWSaveEditor {
	class Character {
		public String name;
		public Byte[] character;

		public Character ( String filepath ) {
			name = filepath;
			character = File.ReadAllBytes(filepath);
		}
		public Character ( Byte[] character ) {
			this.character = character;
		}
		public Character ( Byte[] save, UInt32 offset ) {
			character = new Byte[0x209AC0];
			Buffer.BlockCopy(save, (Int32) offset, character, 0, 0x209AC0);
		}

		public void Diff ( Character that, Boolean skip_unchanged = true, Boolean skip_known = true ) {
			Console.WriteLine($"Comparing characters '{name}' and '{that.name}'");
			Byte[] diff = new Byte[0x10];
			for ( Int32 line = 0 ; line < 0x2098C0 ; line += 0x10 ) {
				if ( skip_known && (
					( line == 0x000050 )
				 || ( line == 0x0002C0 )
				 || ( line == 0x0002D0 )
				 || ( line >= 0x002120 && line < 0x0C02E0 )
				 || ( line >= 0x116090 && line < 0x1674A0 )
				 || ( line >= 0x1A8D48 && line < 0x1ACD48 )
				 || ( line >= 0x1AD5DF && line < 0x1B177F )
				 || ( line >= 0x1B6955 && line < 0x1DB8D5 )
				))
					continue;

				Boolean change = false;
				for ( Int32 i = 0 ; i < 0x10 ; ++i ) {
					if ( character[line + i] != that.character[line + i] ) {
						change = true;
						break;
					}
				}
				if ( skip_unchanged && !change )
					continue;
				Console.ForegroundColor = ConsoleColor.White;
				Console.Write($"{line:X6} | ");
				for ( Int32 i = 0 ; i < 0x10 ; ++i ) {
					Byte b = character[line + i];
					diff[i] = b;
					Console.Write($"{b:X2} ");
				}
				Console.ForegroundColor = ConsoleColor.White;
				Console.Write($"| ");
				for ( UInt32 i = 0 ; i < 0x10 ; ++i ) {
					Byte b = that.character[line + i];
					if ( b != diff[i] ) {
						change = true;
						Console.ForegroundColor = ConsoleColor.Red;
					}  else
						Console.ForegroundColor = ConsoleColor.White;
					Console.Write($"{b:X2} ");
				}

				Console.ForegroundColor = ConsoleColor.White;
				if ( line == 0x000050 )
					Console.Write($"| 0x00005C: Playtime");
				if ( line == 0x0002C0 )
					Console.Write($"| 0x0002CB: Guildcard Playtime | 0x0002CF: Guildcard Updated");
				if ( line == 0x0002D0 )
					Console.Write($"| 0x0002CF: Guildcard Updated");
				if ( line >= 0x002110 && line < 0x0C02F0 )
					Console.Write($"| 0x00211D-0x0C02E9: Guildcards");
				if ( line >= 0x116090 && line < 0x11A630 )
					Console.Write($"| 0x116098-0x11A628: Items");
				if ( line >= 0x11A628 && line < 0x1674A0 )
					Console.Write($"| 0x11A628-0x1674A0: Equipment");
				if ( line >= 0x1A8D48 && line < 0x1ACD48 )
					Console.Write($"| 0x1A8D48-0x1ACD48: NPC Conversations");
				if ( line >= 0x1AD5DF && line < 0x1B177F )
					Console.Write($"| 0x1AD5DF-0x1B177F: Investigations");
				if ( line >= 0x1B6955 && line < 0x1DB8D5 )
					Console.Write($"| 0x1B6955-0x1DB8D5: Equipment loadouts");

				Console.WriteLine($"");
			}
		}

		public void Print ( ) {
			Console.WriteLine($"000000-000004 | Unknown         | {BitConverter.ToUInt32(character, 0x0)}");
			Console.WriteLine($"000004-000044 | Name            | {Encoding.UTF8.GetString(character, 0x4, 0x40)}");
			Console.WriteLine($"000044-000048 | HR              | {BitConverter.ToUInt32(character, 0x44)}");
			Console.WriteLine($"000048-00004C | MR              | {BitConverter.ToUInt32(character, 0x48)}");
			Console.WriteLine($"00004C-000050 | Zenny           | {BitConverter.ToUInt32(character, 0x4C)}");
			Console.WriteLine($"000050-000054 | Research Points | {BitConverter.ToUInt32(character, 0x50)}");
			Console.WriteLine($"000054-000058 | HR XP           | {BitConverter.ToUInt32(character, 0x54)}");
			Console.WriteLine($"000058-00005C | MR XP           | {BitConverter.ToUInt32(character, 0x58)}");
			UInt32 playtime = BitConverter.ToUInt32(character, 0x5C);
			Console.WriteLine($"00005C-000060 | Playtime        | {playtime / 3600:d02}:{playtime / 60 % 60:d02}:{playtime % 60:d02}");
			Console.WriteLine($"000060-000064 | Unknown         | {BitConverter.ToUInt32(character, 0x60)}");
			Console.WriteLine($"000064-0002B2 | Somewhat known");
			
			{ // Hunter appearance
				Int32 loc = 0x000064;

				Int32 id_0 = BitConverter.ToInt32(character, loc);
				// 8 Int32
				Int32 id_24 = BitConverter.ToInt32(character, loc + 0x24);
				// 8 Int32
				Int32 id_48 = BitConverter.ToInt32(character, loc + 0x48);
				// 8 Int32
				
				Int32 rgb_6C = BitConverter.ToInt32(character, loc + 0x6C);
				Int32 rgb_70 = BitConverter.ToInt32(character, loc + 0x70);
				Int32 rgb_74 = BitConverter.ToInt32(character, loc + 0x74);
				Int32 rgb_78 = BitConverter.ToInt32(character, loc + 0x78);
				
				Byte b_7C = character[loc + 0x7C];
				Byte b_7D = character[loc + 0x7D];
				Byte b_7E = character[loc + 0x7E];
				Byte b_7F = character[loc + 0x7F];
				Byte b_80 = character[loc + 0x80];
				Byte b_81 = character[loc + 0x81];
				Byte b_82 = character[loc + 0x82];
				Byte b_83 = character[loc + 0x83];
				
				Int32 boolean_84 = BitConverter.ToInt32(character, loc + 0x84);

				Byte b_88 = character[loc + 0x88];
				Byte b_89 = character[loc + 0x89];
				Byte b_8A = character[loc + 0x8A];
				Byte b_8B = character[loc + 0x8B];
				Byte b_8C = character[loc + 0x8C];
				Byte b_8D = character[loc + 0x8D];
				Byte b_8E = character[loc + 0x8E];
				Byte b_8F = character[loc + 0x8F];
				
				Int32 boolean_90 = BitConverter.ToInt32(character, loc + 0x90);
				
				Int32 rgb_94 = BitConverter.ToInt32(character, loc + 0x94);
				
				Byte b_98 = character[loc + 0x98];
				Byte b_99 = character[loc + 0x99];
				Byte b_9A = character[loc + 0x9A];
				Byte b_9B = character[loc + 0x9B];
				Byte b_9C = character[loc + 0x9C];
				Byte b_9D = character[loc + 0x9D];
				Byte b_9E = character[loc + 0x9E];
				Byte b_9F = character[loc + 0x9F];
				
				Int32 id_A0 = BitConverter.ToInt32(character, loc + 0xA0);
			}
			// 000108 - 000286 some floats and padding bytes
			{

			}
			{ // Guildcard 0x1E6B
				Int32 loc = 0x0002B2;
				
				UInt64 steamid = BitConverter.ToUInt64(character, loc);
				Double timestamp_8 = BitConverter.ToDouble(character, loc + 0x8);
				
				Byte b_10 = character[loc + 0x10];
				
				UInt32 HR = BitConverter.ToUInt32(character, loc + 0x11);

				UInt32 full0_15 = BitConverter.ToUInt32(character, loc + 0x15);

				UInt32 gc_playtime = BitConverter.ToUInt32(character, 0x19);
				
				Double timestamp_1F = BitConverter.ToDouble(character, loc + 0x1D);
				
				String gc_name = Encoding.UTF8.GetString(character, loc + 0x25, 0x40);
				String group_name = Encoding.UTF8.GetString(character, loc + 0x65, 0x36);
				
				UInt64 group_steamid_maybe = BitConverter.ToUInt64(character, loc + 0x9B);
				UInt64 full0_A3 = BitConverter.ToUInt64(character, loc + 0xA3);

				UInt32 unknown_AB = BitConverter.ToUInt32(character, 0xAB);

				// 000431 weapon type
				// 000435 weapon id
			}
			Console.WriteLine($"00211D-0C02E9 | Guildcards      | 100 slots");
			for ( Int32 loc = 0x00211D; loc < 0x0C02E9 ; loc += 0x1E6B ) {
				UInt64 steamid = BitConverter.ToUInt64(character, loc);
				if ( steamid == 0 )
					continue;
				
				UInt32 HR = BitConverter.ToUInt32(character, loc + 0x11);
				String gc_name = Encoding.UTF8.GetString(character, loc + 0x25, 0x40);
				Console.WriteLine($"Guildcard of {gc_name}; ({HR})");
			}

			// 000431 weapon type
			// 000435 weapon id
			// 0E6615 weapon id



			//Register("Hunter Appearance",				"Region",		 0x58,	   120); // |	  58 ][     120 HunterAppearance
			//Register("Palico Appearance",				"Region",		 0xD0,		44); // |	0xD0 ][      44 PalicoAppearance
			//Register("Guildcard",						"Region",		 0xFC,	  4923); // |	  FC ][    4923 Guildcard
			//Register("Shared Guildcards",				"Region",	   0x1437,	492300); // |	1437 ][  492300 Guildcard * 100
			//Register("UNKNOWN_79743_100",				"Region",	  0x79743,	   100); // |  79743 ][     100 Unknown (counting up until full F)
			//Register("UNKNOWN_797A7_500",				"Region",	  0x797A7,	   500); // |  797A7 ][     500 Unknown (100 * 5 tracking)
			//Register("UNKNOWN_7999B_98460",				"Region",	  0x7999B,	 98460); // |  7999B ][   98460 Unknown (20 * 4923)
			//Register("UNKNOWN_91A37_6878",				"Region",	  0x91A37,	  6878); // |  91A37 ][    6878 Unknown (20 * 4923)
			
																// post living quarters
																// Weapon upgrade and equip
																	// 0x91A9F (0C -> 0A -> 13)
																// A3 - Urgent Pukei-Pukei Hunt
																// A3 - Sinister Shadows in the Swamp 
																	// 0x91BAE (08 -> 09 -> 29)
																// lynian and forest 9
																// camp and forest 8 10
																	// 0x91BAB (9D -> DD -> FD)
																// A2 - A Kestodon Kerfuffle
																// A3 - The Best Kind of Quest
																	// 0x91BAC (00-00 -> 01-00 -> 03-20)
																// A2 - A Kestodon Kerfuffle
																// A3 - Urgent Pukei-Pukei Hunt
																// A3 - The Best Kind of Quest
																	// 0x91BB0 (40-00 -> 60-00 -> 70-00 -> 77-20)
																// Small Monster Kills
																	//0x91DD3 Aptonoth
																	//0x91DD7 Jagras
																	//0x91DE0 Mosswine
																	//0x91DE3 Gajau
																	//0x91DE7 Kestadon (Male) (?)
																	//0x91DEB Apceros (?)
																	//0x91E37
																	//0x91E77 Hornetaur
																	//0x91E7B Vespoid
																	//0x91E83 Kestadon (Female) (?)
																	//0x91E87 Raphinos
																	//0x91E8B Shamos
																	//0x91E93 Girros
																
																// ?
																	//0x929DD-0x92A22
																
															// 0x92A23-0x92E03 padding (?)
																// Endemic Life Infobox Flag
																		//0x92E04-0x092E5A
																	//0x92E53.20 Woodland Pteryx
																	//0x92E58.02 Hercudrome

																// Endemic Life Capture Count
																		//0x92EB9-0x93379
																	//0x92EB9 Shepherd Hare
																	//0x92ED9 Woodland Pteryx
																	//0x92F3D Wildspire Gekko
																	//0x92F79 Revolture
																	//0x92F99 Omenfly (?)
																	//0x93099 Hopguppy
																	//0x930F9 Wiggler
																	//0x9311D Giant Vigorwasp
																	//0x93159 Carrier Ant
																	//0x93179 Hercudrome
																	//0x93199

																	//0x9329D
																	//0x932A5

																	//0x93379 Sushifish
			//Register("Item Loadouts",					"Region",	  0x93579,   63224); // |  93579 ][   63224 itemLoadouts
			// F3530
			//PrintBytes($"Item Loadouts", character, 0xF3510, 10000);
			//for ( Int32 loc = (Int32) _offset + 0xF34F0 ; loc < (Int32) _offset + 0xFF510 ; loc += 10000 ) {
			//	PrintBytes($"Item Loadouts", character, loc, 10000);
			//}

			// 0x019088
			// 0x01AEF3
			// 0x01CD5D (0x1E6B / 7787)

			//Register("UNKNOWN_A2C71_8",					"Unknown",	  0xA2C71,		 8); // |  A2C71 ][	      8 unknown
			Console.WriteLine($"0C02E9-116098 | Somewhat known");
				Console.WriteLine($"116098-116158 | Item Pouch      | 24 slots");
				Console.WriteLine($"116158-1161D8 | Ammo Pouch      | 16 slots");
				Console.WriteLine($"1161D8-116298 | Material Pouch  | 24 slots");
				Console.WriteLine($"116298-1162F8 | Special Pouch   | 12 slots");
				Console.WriteLine($"1162F8-116938 | Item Box        | 200 slots");
				Console.WriteLine($"116938-116F78 | Ammo Box        | 200 slots");
				Console.WriteLine($"116F78-119688 | Material Box    | 1250 slots");
				Console.WriteLine($"119688-11A628 | Decoration Box  | 500 slots");
				/**
				for ( Int32 loc = 0x119688 ; loc < 0x11A628 + 0x8 ; loc += 0x8 ) {
					UInt32 id = BitConverter.ToUInt32(character, loc);
					UInt32 amount = BitConverter.ToUInt32(character, loc + 0x4);
					if ( id == 0 )
						continue;

					Console.WriteLine($"                                | { Data.items[id] }: { amount }");
				}
				*/
				Console.WriteLine($"11A628-1674A0 | Equipment Box   | 2500 slots");
				/**
				for ( Int32 loc = 0x11A628 ; loc < 0x1674A0 ; loc += 0x7E ) {
					// 0: 0
					// 4: 0
					// 8: index
					UInt32 index = BitConverter.ToUInt32(character, loc + 0x8);
					// C : category
					Int32 maintype = BitConverter.ToInt32(character, loc + 0xC);

					if ( maintype == -1 )
						continue;

					String maintypestring = new String[] { "Armor", "Weapon", "Charm", "?", "Kinsect" }[maintype];

					// 10 : subcategory
					Int32 subtype = BitConverter.ToInt32(character, loc + 0x10);
					String subtypestring = subtype.ToString();
					if (maintypestring == "Armor" && subtype < 5 )
						subtypestring = new String[] { "Head", "Chest", "Arms", "Waist", "Legs" }[subtype];
					if (maintypestring == "Weapon" && subtype < 14 )
						subtypestring = new String[] { "Great Sword", "Sword and Shield", "Dual Blades", "Long Sword", "Hammer", "Hunting Horn", "Lance", "Gunlance", "Switch Axe", "Charge Blade", "Insect Glaive", "Bow", "Heavy Bowgun", "Light Bowgun" }[subtype];
					if ( maintypestring == "Kinsect" && subtype < 6 )
						subtypestring = new String[] { "None", "Fire", "Water", "Ice", "Thunder", "Dragon" }[subtype];

					// 14 : id
					Int32 id = BitConverter.ToInt32(character, loc + 0x14);
					Console.WriteLine($"                                | {maintypestring} {subtypestring}: {id}");

					// 18 : level
					UInt32 level = BitConverter.ToUInt32(character, loc + 0x18);
					// 1C : points
					UInt32 points = BitConverter.ToUInt32(character, loc + 0x1C);

					if ( level != 0 || points != 0 )
						Console.WriteLine($"                                  > Level {level}; {points} points");

					// 20 : decoration slot 1
					Int32 deco1id = BitConverter.ToInt32(character, loc + 0x20);
					if ( deco1id != -1 )
						Console.WriteLine($"                                  > Decoration {deco1id}");
					// 24 : decoration slot 2
					Int32 deco2id = BitConverter.ToInt32(character, loc + 0x24);
					if ( deco2id != -1 )
						Console.WriteLine($"                                  > Decoration {deco2id}");
					// 28 : decoration slot 3
					Int32 deco3id = BitConverter.ToInt32(character, loc + 0x28);
					if ( deco3id != -1 )
						Console.WriteLine($"                                  > Decoration {deco3id}");

					// 2C : mod slot 3
					Int32 mod1id = BitConverter.ToInt32(character, loc + 0x2C);
					if ( mod1id != -1 )
						Console.WriteLine($"                                  > Mod {mod1id}");
					// 30 : mod slot 3
					Int32 mod2id = BitConverter.ToInt32(character, loc + 0x30);
					if ( mod2id != -1 )
						Console.WriteLine($"                                  > Mod {mod2id}");
					// 34 : mod slot 3
					Int32 mod3id = BitConverter.ToInt32(character, loc + 0x34);
					if ( mod3id != -1 )
						Console.WriteLine($"                                  > Mod {mod3id}");
					// 38 : mod slot 3
					Int32 mod4id = BitConverter.ToInt32(character, loc + 0x38);
					if ( mod4id != -1 )
						Console.WriteLine($"                                  > Mod {mod4id}");
					// 3C : mod slot 3
					Int32 mod5id = BitConverter.ToInt32(character, loc + 0x3C);
					if ( mod5id != -1 )
						Console.WriteLine($"                                  > Mod {mod5id}");

					// 40 : augment slot 1
					Int32 aug1id = BitConverter.ToInt32(character, loc + 0x40);
					if ( aug1id != 0 )
						Console.WriteLine($"                                  > Aug {aug1id}");
					// 44 : augment slot 2
					Int32 aug2id = BitConverter.ToInt32(character, loc + 0x44);
					if ( aug2id != 0 )
						Console.WriteLine($"                                  > Aug {aug2id}");
					// 48 : augment slot 3
					Int32 aug3id = BitConverter.ToInt32(character, loc + 0x48);
					if ( aug3id != 0 )
						Console.WriteLine($"                                  > Aug {aug3id}");

					// 4C ?
					Int32 unknown_4C = BitConverter.ToInt32(character, loc + 0x4C);
					if ( unknown_4C != -1 )
						Console.WriteLine($"                                  ? unknown_4C: {unknown_4C}");

					// 50 ?
					Int32 unknown_50 = BitConverter.ToInt32(character, loc + 0x50);
					if ( unknown_50 != -1 )
						Console.WriteLine($"                                  ? unknown_50: {unknown_50}");

					// 54 : pendant (Int16)
					Int16 pendant = BitConverter.ToInt16(character, loc + 0x54);
					if ( pendant != -1 )
						Console.WriteLine($"                                  > Pendant: {pendant}");

					// 56 : padding? (Int16)
					Int16 unknown_56 = BitConverter.ToInt16(character, loc + 0x56);
					if ( unknown_56 != -1 )
						Console.WriteLine($"                                  ? unknown_56: {unknown_56}");
				
					// 58 : advanced augment, extra slots
					Byte aaugextraslots = character[loc + 0x58];
					if ( aaugextraslots != 0 )
						Console.WriteLine($"                                  > Aug Extra Slots: {aaugextraslots}");
					// 59 : advanced augment, attack
					Byte aaugattack = character[loc + 0x59];
					if ( aaugattack != 0 )
						Console.WriteLine($"                                  > Aug Attack: {aaugattack}");
					// 5A : advanced augment, extra slots
					Byte aaugaffinity = character[loc + 0x5A];
					if ( aaugaffinity != 0 )
						Console.WriteLine($"                                  > Aug Affinity: {aaugaffinity}");
					// 5B : advanced augment, extra slots
					Byte aaugdefense = character[loc + 0x5B];
					if ( aaugdefense != 0 )
						Console.WriteLine($"                                  > Aug Defense: {aaugdefense}");
					// 5C : advanced augment, extra slots
					Byte aaugslot = character[loc + 0x5C];
					if ( aaugslot != 0 )
						Console.WriteLine($"                                  > Aug Slots: {aaugslot}");
					// 5D : advanced augment, extra slots
					Byte aaugregen = character[loc + 0x5D];
					if ( aaugregen != 0 )
						Console.WriteLine($"                                  > Aug Regen: {aaugregen}");
					// 5E : advanced augment, extra slots
					Byte aaugelement = character[loc + 0x5E];
					if ( aaugelement != 0 )
						Console.WriteLine($"                                  > Aug Element: {aaugelement}");
					// 5F padding?
					Byte unknown_5F = character[loc + 0x5F];
					if ( unknown_5F != 0 )
						Console.WriteLine($"                                  ? Padding {unknown_5F}");

					// 60 ?
					UInt32 unknown_60 = BitConverter.ToUInt32(character, loc + 0x60);
					if ( unknown_60 != 0 )
						Console.WriteLine($"                                  ? unknown_60 {unknown_60}");
					// 64 ?
					UInt32 unknown_64 = BitConverter.ToUInt32(character, loc + 0x64);
					if ( unknown_64 != 0 )
						Console.WriteLine($"                                  ? unknown_64 {unknown_64}");
					// 68 ? (Int16)
					Int16 unknown_68 = BitConverter.ToInt16(character, loc + 0x68);
					if ( unknown_68 != 0 )
						Console.WriteLine($"                                  > unknown_68: {unknown_68}");
					// 6A ? (Int16)
					Int16 unknown_6A = BitConverter.ToInt16(character, loc + 0x6A);
					if ( unknown_6A != -1 )
						Console.WriteLine($"                                  > unknown_6A: {unknown_6A}");
					// 6C ?
					Int32 unknown_6C = BitConverter.ToInt32(character, loc + 0x6C);
					if ( unknown_6C != -1 )
						Console.WriteLine($"                                  ? unknown_6C {unknown_6C}");
					// 70 ?
					Int32 unknown_70 = BitConverter.ToInt32(character, loc + 0x70);
					if ( unknown_70 != -1 )
						Console.WriteLine($"                                  ? unknown_70 {unknown_70}");
					// 74 ?
					Int32 unknown_74 = BitConverter.ToInt32(character, loc + 0x74);
					if ( unknown_74 != -1 )
						Console.WriteLine($"                                  ? unknown_74 {unknown_74}");
				
					// 76 : Layered Base (Int16)
					Int16 layeredbase = BitConverter.ToInt16(character, loc + 0x76);
					if ( layeredbase != -1 )
						Console.WriteLine($"                                  > Layered Base: {layeredbase}");
					// 78 : Layered Part (Int16)
					Int16 layeredpart = BitConverter.ToInt16(character, loc + 0x78);
					if ( layeredpart != -1 )
						Console.WriteLine($"                                  > Layered Part: {layeredpart}");
				
					// 7A : Safi slot 1
					Byte safi1id = character[loc + 0x7A];
					if ( safi1id != 0 )
						Console.WriteLine($"                                  > Safi 1: {safi1id}");
					// 7B : Safi slot 2
					Byte safi2id = character[loc + 0x7B];
					if ( safi2id != 0 )
						Console.WriteLine($"                                  > Safi 2: {safi2id}");
					// 7C : Safi slot 3
					Byte safi3id = character[loc + 0x7C];
					if ( safi3id != 0 )
						Console.WriteLine($"                                  > Safi 3: {safi3id}");
					// 7D : Safi slot 4
					Byte safi4id = character[loc + 0x7D];
					if ( safi4id != 0 )
						Console.WriteLine($"                                  > Safi 4: {safi4id}");
				}
				*/
				Console.WriteLine($"1674A0-176FA4 | -1 Equipment    | 510 slots");
				Console.WriteLine($"176FA4-19D6E0 | Empty Equipment | 1250 slots");
			Console.WriteLine($"19D6E0-1A8D48 | Unknown");
			
			// 1A4656:20 Notice flag; Iron Bow II
			// 1A4656:10 Notice flag; Iron Bow I

			
			// 1A465B:8 Notice flag; Hunters Bow II
			// 1A465B:4 Notice flag; Hunters Bow I

				Console.WriteLine($"1A8D48-1ACD48 | NPC Conv.       | 2048 slots");
			Console.WriteLine($"1ACD48-1AD5DF | Unknown");
			
			// 1ACE41:8 Expedition explanation

			// 1ACF32:1 / 1AD1C9:4 Obtained; Learning the Clutch

			// 1ACFC0 - 1ACFC8 session settings

			// 1AD228:1 Notice flag; The Great Glutton
			// 1AD227:40 Notice flag; Bird-Brained Bandit
			// 1AD227:10 Notice flag; A Thicket of Thugs
			// 1AD227:8 Notice flag; Butting Heads with Nature
			// 1AD227:4 Notice flag; The Great Jagras Hunt
			// 1AD227:2 Notice flag; A Kestadon Kerfuffle
			// 1AD227:1 Notice flag; Jagras of the Great Forest

			// 1AD249:4 Notice flag; Learning the Clutch
				Console.WriteLine($"1AD5DF-1B177F | Investigations  | 400 slots");
				/**
				for ( Int32 loc = 0x1AD5DF; loc < 0x1B177F ; loc += 0x2A ) {
					Int32 somecheck = BitConverter.ToInt32(character, loc);
					if ( somecheck == -1 )
						continue;
					String status = "";
					if ( somecheck == 30000 )
						status = "seen?";

					Console.WriteLine($"                                | Investigation {somecheck} ({status})");

					Byte registered = character[loc + 0x4];
					if (registered == 1)
						Console.WriteLine($"                                  > Registered");

					UInt32 attempts = BitConverter.ToUInt32(character, loc + 0x5);
					Console.WriteLine($"                                  > Attempts: {attempts}");
				
					UInt32 seen = BitConverter.ToUInt32(character, loc + 0x9);
					Console.WriteLine($"                                  > Seen: {seen}");

					Byte locale = character[loc + 0xD];
					Console.WriteLine($"                                  > Locale: {locale}");

					Byte rank = character[loc + 0xE];
					Console.WriteLine($"                                  > Rank: {rank}");

					Int32 monster1id = BitConverter.ToInt32(character, loc + 0xF);
					Int32 monster2id = BitConverter.ToInt32(character, loc + 0x13);
					Int32 monster3id = BitConverter.ToInt32(character, loc + 0x17);
					Byte monster1tempered = character[loc + 0x1B];
					Byte monster2tempered = character[loc + 0x1C];
					Byte monster3tempered = character[loc + 0x1D];

					if (monster1id != -1)
						Console.WriteLine($"                                  > Monster 1: {monster1id} {monster1tempered}");
					if (monster2id != -1)
						Console.WriteLine($"                                  > Monster 2: {monster2id} {monster2tempered}");
					if (monster3id != -1)
						Console.WriteLine($"                                  > Monster 3: {monster3id} {monster3tempered}");
				
					Byte hp = character[loc + 0x1E];
					Byte attack = character[loc + 0x1F];
					Byte defense = character[loc + 0x20];
					Byte size = character[loc + 0x21];
					Byte unknown_23 = character[loc + 0x22];
					Byte flourish = character[loc + 0x23];
					Byte time = character[loc + 0x24];
					Byte unknown_26 = character[loc + 0x25];
					Byte faints = character[loc + 0x26];
					Byte players = character[loc + 0x27];
					Byte rewards = character[loc + 0x28];
					Byte zenny = character[loc + 0x29];

					Console.WriteLine($"                                  > Settings: HP{hp} ATT{attack} DEF{defense} S{size} ?{unknown_23} F{flourish} T{time} ?{unknown_26} F{faints} P{players} R{rewards} Z{zenny}");
				}
				*/
			Console.WriteLine($"1B177F-1B21D1 | Unknown");
				Console.WriteLine($"1B21D1-1B60D1 | Something?      | 128 slots");
				/**
				for ( Int32 loc = 0x1B21D1; loc < 0x1B60D1 ; loc += 0x7E ) {
					UInt32 index = BitConverter.ToUInt32(character, loc);
					PrintBytes($"Unknown {index}", character, loc, 0x7E);
				}
				*/
			

			Console.WriteLine($"1B60D1-1B6955 | Unknown");
				Console.WriteLine($"1B6955-1DB8D5 | Equip Layouts   | 224 slots");
				/**
				for ( Int32 loc = 0x1B6955 ; loc < 0x1DB8D5 ; loc += 0x2A4 ) {
					UInt32 index = BitConverter.ToUInt32(character, loc);
					Byte[] namebytes = new Byte[0x100];
					Buffer.BlockCopy(character, loc+0x4, namebytes, 0, 0x100);
					String name = Encoding.UTF8.GetString(namebytes).TrimEnd('\0');
					Console.WriteLine($"Loadout {index}: {name}");

					// | UInt32 index | 0x100 name |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | FF FF FF FF | FF FF FF FF | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 |
					// | 00 00 00 00 | 00 00 00 00 | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF | FF FF FF FF |
					// | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 |
					// | FF FF FF FF |
					// PrintBytes($"Unknown {index}", character, loc, 0x2A4);
				}
				*/
				Console.WriteLine($"1DB8D5-1E4315 | Something?      | 112 slots");
				/**
				for ( Int32 loc = 0x1DB8D5 ; loc < 0x1E4315 ; loc += 0x13C ) {
					UInt32 index = BitConverter.ToUInt32(character, loc);
				
					PrintBytes($"Unknown {index}", character, loc, 0x13C);
				}
				*/
				Console.WriteLine($"1E4315-1E5ED5 | Something?      | 24 slots");
				/**
				for ( Int32 loc = 0x1E4315 ; loc < 0x1E5ED5 ; loc += 0x128 ) {
					UInt32 index = BitConverter.ToUInt32(character, loc);
				
					PrintBytes($"Unknown {index}", character, loc, 0x128);
				}
				*/
			Console.WriteLine($"1E5ED5-1E7082 | Unknown");
				Console.WriteLine($"1E7082-1EA202 | Something?      | 96 slots; no index and some small differences");
				/**
				for ( Int32 loc = 0x1E7082 ; loc < 0x1EA202 ; loc += 0x84 ) {
					UInt32 index = BitConverter.ToUInt32(character, loc);
				
					PrintBytes($"Unknown {index}", character, loc, 0x84);
				}
				*/
			Console.WriteLine($"1EA202-2098C0 | Unknown");
			//PrintBytes("Unknown", character, 0x1EA202, 0x2098C0-0x1EA202);
				Console.WriteLine($"2098C0-209AC0 | Hash");
		}
	}
}
