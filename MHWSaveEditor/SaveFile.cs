using System;
using System.IO;
using System.Text;

namespace MHWSaveEditor {
	class SaveFile {

		private String _filepath;
		private Byte[] _save;
		private String state = "Uninitialized";

		public SaveFile ( String filepath ) {
			_filepath = filepath;
			state = "Linked";
		}
		public void Read ( ) {
			_save = File.ReadAllBytes(_filepath);
			state = "Read";
		}
		public void DecryptBlowfish ( ) {
			Blowfish.Decrypt(_save);
			state = "Blowfish decrypted";
		}
		public void DecryptAES ( ) {
			MHWCrypto.DecryptCharacter(_save, 0x3010D8);
			MHWCrypto.DecryptCharacter(_save, 0x50AB98);
			MHWCrypto.DecryptCharacter(_save, 0x714658);
			state = "AES decrypted";
		}
		public void CharacterChecksums ( ) {
			Byte[] checksum0 = MHWCrypto.GenerateChecksumCharacter0(_save);
			Buffer.BlockCopy(checksum0, 0, _save, 0x3010D8+0x2098C0, 0x200);
			state = "Valid character checksums";
		}
		public void EncryptAES ( ) {
			MHWCrypto.EncryptCharacter(_save, 0x3010D8);
			MHWCrypto.EncryptCharacter(_save, 0x50AB98);
			MHWCrypto.EncryptCharacter(_save, 0x714658);
			state = "AES encrypted";
		}
		public void GlobalChecksums ( ) {
			byte[] checksum = MHWCrypto.GenerateHash(_save);
			Buffer.BlockCopy(checksum, 0, _save, 0xC, 0x14);
		}
		public void EncryptBlowfish ( ) {
			Blowfish.Encrypt(_save);
			state = "Blowfish encrypted";
		}

		public Character GetCharacter ( UInt32 slot ) {
			return new Character(_save, 0x3010D8 + slot * 0x209AC0);
		}

		public void SetCharacter ( Int32 slot, Character character ) {
			Buffer.BlockCopy(character.character, 0, _save, 0x3010D8 + slot * 0x209AC0, 0x209AC0);
		}

		public void Write ( String filepath ) {
			(new FileInfo(filepath)).Directory.Create();
			File.WriteAllBytes(filepath, _save);
		}
		public void WriteCharacter0 ( String filepath ) {
			(new FileInfo(filepath)).Directory.Create();
			Byte[] character0 = new Byte[0x209AC0];
			Buffer.BlockCopy(_save, 0x3010D8, character0, 0, 0x209AC0);
			File.WriteAllBytes(filepath, character0);
		}
		public void WriteCharacter1 ( String filepath ) {
			(new FileInfo(filepath)).Directory.Create();
			Byte[] character0 = new Byte[0x209AC0];
			Buffer.BlockCopy(_save, 0x50AB98, character0, 0, 0x209AC0);
			File.WriteAllBytes(filepath, character0);
		}
		public void WriteCharacter2 ( String filepath ) {
			(new FileInfo(filepath)).Directory.Create();
			Byte[] character0 = new Byte[0x209AC0];
			Buffer.BlockCopy(_save, 0x714658, character0, 0, 0x209AC0);
			File.WriteAllBytes(filepath, character0);
		}

		public static void PrintBytes( String title, Byte[] data, Int32 start, Int32 size ) {
			Console.WriteLine($"{title}:");
			byte j = 0;
			for ( Int32 i = start ; i < start + size ; i++ ) {
				if ( j == 0 )
					Console.Write($"{i:X2}: | ");

				Console.Write($"{data[i]:X2} ");

				if ( ++j % 4 == 0 )
					Console.Write("| ");
				if ( j == 32 ) { Console.WriteLine(); j = 0; }
			}
			Console.WriteLine();
		}

		public void PrintCharacterAnalysis ( UInt32 start, UInt32 stop ) {
			for ( UInt32 line = start ; line < stop ; line += 0x10 ) {
				Console.ForegroundColor = ConsoleColor.White;
				Console.Write($"{line:X6} | ");
				for ( UInt32 i = 0 ; i < 0x10 ; ++i ) {
					Int32 pos = (Int32) (line + i);
					Byte b = _save[0x3010D8 + pos];
					if (
					   (pos >= 0x000004 && pos < 0x000044) // Name
					|| (pos >= 0x000044 && pos < 0x000048) // HR
					|| (pos >= 0x000048 && pos < 0x00004C) // MR
					|| (pos >= 0x00004C && pos < 0x000050) // Zenny
					|| (pos >= 0x000050 && pos < 0x000054) // Research Points
					|| (pos >= 0x000054 && pos < 0x000058) // HR XP
					|| (pos >= 0x000058 && pos < 0x00005C) // MR XP
					|| (pos >= 0x00005C && pos < 0x000060) // Playtime
					
					// || (pos >= 0x000064 && pos < 0x0000DC) // Hunter Appearance

					|| (pos >= 0x116098 && pos < 0x116158) // Item Pouch
					|| (pos >= 0x116158 && pos < 0x1161D8) // Ammo Pouch
					|| (pos >= 0x1161D8 && pos < 0x116298) // Material Pouch
					|| (pos >= 0x116298 && pos < 0x1162F8) // Special Pouch
					|| (pos >= 0x1162F8 && pos < 0x116938) // Item Box
					|| (pos >= 0x116938 && pos < 0x116F78) // Ammo Box
					|| (pos >= 0x116F78 && pos < 0x119688) // Material Box
					|| (pos >= 0x119688 && pos < 0x11A628) // Decoration Box
					|| (pos >= 0x11A628 && pos < 0x1674A0) // Equipment Box
					|| (pos >= 0x1674A0 && pos < 0x176FA4) // -1 Equipment
					|| (pos >= 0x176FA4 && pos < 0x19D6E0) // Empty Equipment

					|| (pos >= 0x1A8D48 && pos < 0x1ACD48) // NPC Conversations

					|| (pos >= 0x1AD5DF && pos < 0x1B177F) // Investigations

					|| (pos >= 0x1B21D1 && pos < 0x1B60D1) // Something?

					|| (pos >= 0x1B6955 && pos < 0x1DB8D5) // Equipment Layouts

					|| (pos >= 0x2098C0 && pos < 0x209AC0) // Hash
					)
						Console.ForegroundColor = ConsoleColor.Green;
					else
						Console.ForegroundColor = ConsoleColor.Red;
					Console.Write($"{b:X2} ");
				}
				Console.ForegroundColor = ConsoleColor.White;
				Console.Write($"| ");
				for ( UInt32 i = 0 ; i < 0x10 ; ++i ) {
					Int32 pos = (Int32) (line + i);
					Byte b = _save[0x50AB98 + pos];
					Console.Write($"{b:X2} ");
				}
				Console.Write($"| ");
				for ( UInt32 i = 0 ; i < 0x10 ; ++i ) {
					Int32 pos = (Int32) (line + i);
					Byte b = _save[0x714658 + pos];
					Console.Write($"{b:X2} ");
				}
				Console.WriteLine($"");
			}
		}
	}
}
