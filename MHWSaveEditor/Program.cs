using System;
using System.IO;

namespace MHWSaveEditor {
	static class Program {
		/**
		[STAThread]
		static void Main() {
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			Application.Run(new Form1());
		}
		*/
		static void Main() {
			String directory = GetSaveDirectory();
			SaveFile save = new SaveFile($"{directory}/SAVEDATA1000");
			save.Read();
			//save.Write($"{directory}/BACKUP");
			save.DecryptBlowfish();
			save.DecryptAES();

			//save.Write($"analysis/lastsave");
			//save.WriteCharacter2($"analysis/A023");
			//save.PrintCharacterAnalysis(0x1A0000, 0x209AC0);
			
			//SO_Character a001 = new SO_Character($"analysis/A001 - reset");
			//SO_Character a002 = new SO_Character($"analysis/A002 - defaultcreation");
			//SO_Character a003 = new SO_Character($"analysis/A003 - In astera");
			//SO_Character a004 = new SO_Character($"analysis/A004 - Meeting");
			//SO_Character a005 = new SO_Character($"analysis/A005 - Equiping Bow");
			//SO_Character a006 = new SO_Character($"analysis/A006 - Talk to Handler");
			//SO_Character a007 = new SO_Character($"analysis/A007 - Quest Tutorial");
			//SO_Character a008 = new SO_Character($"analysis/A008 - Notice flag; Jagras of the Great Forest");
			//SO_Character a009 = new SO_Character($"analysis/A009 - Jagras of the Great Forest");
			//SO_Character a010 = new SO_Character($"analysis/A010 - Claim daily");
			//SO_Character a011 = new SO_Character($"analysis/A011 - Talk to Smithy");
			//SO_Character a012 = new SO_Character($"analysis/A012 - Talk to Smithy");
			//SO_Character a013 = new SO_Character($"analysis/A013 - Talk to Handler");
			//SO_Character a014 = new SO_Character($"analysis/A014 - Notice flag; A Kestadon Kerfuffle");
			//SO_Character a015 = new SO_Character($"analysis/A015 - Lucky Voucher Tutorial");
			//SO_Character a016 = new SO_Character($"analysis/A016 - A Kestadon Kerfuffle");
			//SO_Character a017 = new SO_Character($"analysis/A017 - Multiplayer Tutorial");
			//SO_Character a018 = new SO_Character($"analysis/A018 - Claim daily");
			//SO_Character a019 = new SO_Character($"analysis/A019 - The Great Jagras Hunt");
			//SO_Character a020 = new SO_Character($"analysis/A020 - Talk to Provisions Manager");
			//SO_Character a021 = new SO_Character($"analysis/A021 - Expedition Ancient Forest");
			//SO_Character a022 = new SO_Character($"analysis/A022");
			//SO_Character a023 = new SO_Character($"analysis/A023");
			//a023.Diff(save.GetCharacter(2));

			
			//save.GetCharacter(2).Diff(save.GetCharacter(0), false, false);

			//save.CharacterChecksums();
			save.EncryptAES();
			//save.GlobalChecksums();
			save.EncryptBlowfish();
			save.DecryptBlowfish();
			save.DecryptAES();
			Character character0 = save.GetCharacter(0);
			character0.Print();
			Character character1 = save.GetCharacter(1);
			//character1.Print();
			Character character2 = save.GetCharacter(2);
			//character2.Print();

			Console.ReadLine();
		}

		public static String GetSaveDirectory() {
			String directory = (String) Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", "") + "/userdata";

			foreach ( String user in Directory.GetDirectories(directory) ) {
				String[] paths = Directory.GetDirectories(user, "582010");
				if ( paths.Length != 0 ) {
					directory = paths[0] + "/remote";
					break;
				}
			}

			return directory;
		}
		public static void CreateBackup( String name ) {
			Console.WriteLine($"Creating backup as /{name}");

			String directory = GetSaveDirectory();

			File.Copy($"{directory}/SAVEDATA1000", $"{directory}/{name}", true);
		}
		public static void RestoreBackup( String name ) {
			Console.WriteLine($"Restoring backup /{name}");

			String directory = GetSaveDirectory();

			File.Copy($"{directory}/{name}", $"{directory}/SAVEDATA1000", true);
		}
	}
}
