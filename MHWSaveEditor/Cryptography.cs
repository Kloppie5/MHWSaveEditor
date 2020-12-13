using System;
using System.Security.Cryptography;
using System.Text;

namespace MHWSaveEditor {
	public static class Blowfish {
		/**
		 *	Precomputed Blowfish encryption for byte swapping and key xieZjoe#P2134-3zmaghgpqoe0z8$3azeq
		 */

		private static readonly UInt32[] P = new UInt32[] {
			0xF3BF925F, 0xB70066B9, 0xEEFE034C, 0xE244DD49, 0x13DAB192, 0x8224CA0B,
			0x00B4A0BC, 0xE8DDD9C9, 0x152F7A65, 0xBE8E1FA2, 0xEB3E80B9, 0x7B79BFAF,
			0x5FB8D2B1, 0xA2D1B92A, 0xAB8ABC56, 0x732BC465, 0xAF78E6CB, 0x88A9FADA
		};
		private static readonly UInt32[] S1 = {
			0x8370E579, 0x44A4B9E1, 0xF86CB0C4, 0xAD3A1D82, 0xBFC9F4D9, 0x830FD084, 0xDDD55160, 0xD4E99F58,
			0x318BA9FD, 0x5B5EA752, 0x0039F139, 0x9FCFD3FF, 0xA2D8D4C7, 0x355027D3, 0xB5C9C8F9, 0x7E2F0C86,
			0x835911B0, 0x16CE9675, 0xB518A552, 0xCE5E35FF, 0x09AFD0FF, 0xBC94FE59, 0xF3F33ED7, 0xCF852D5C,
			0xEFBFF552, 0xB34ACB23, 0x7260EE5E, 0x75D8A99C, 0x99C70C57, 0xCB2CD958, 0xA0169A06, 0xD105A561,
			0xF7AF0DD4, 0xB8FB52FD, 0xAE2C84DA, 0x0D0D100A, 0xFA0C022C, 0x86B903C7, 0xC4C5B4FE, 0x615F6267,
			0x336E9AD4, 0x0B183722, 0x8610630C, 0xB34D3166, 0x92AF7610, 0x85565294, 0x77551AAF, 0x4E28293B,
			0x67BB223D, 0xEFA9C870, 0x803B524B, 0x9EEFEF69, 0x2F7E0AD8, 0x469798AA, 0xEA5F8324, 0x343EDD07,
			0x5ED75387, 0x596CED72, 0x7D4AF89D, 0xFBE89653, 0xA0834324, 0x9A55F0F1, 0x6D153488, 0xE9143B55,
			0x79E074EA, 0x298B7579, 0xECE59DED, 0x5FD30916, 0x6A12B2B5, 0xF250554F, 0x8D6F5BB3, 0xA901AE88,
			0x103008DF, 0x2B9F18FB, 0x728140BD, 0xE9540AB0, 0xD8D79BA8, 0xFAFFA771, 0xA5868EE9, 0x803E9B91,
			0xEF31892A, 0x7ECE0634, 0xEA0F7023, 0xB5662AD8, 0x60A67A22, 0xEBF0F257, 0xC75060A6, 0xA92EAB70,
			0x9805E7FA, 0x94A814CC, 0xFBBF29A6, 0x28D2CE96, 0xF3AF3058, 0xD55FCEA1, 0x2A966F85, 0xA59BA22D,
			0xAB92B4A8, 0x73070FB7, 0x759B775B, 0x8F9C31F0, 0x550A49C0, 0x465A429B, 0x5D2CE134, 0x24FCE988,
			0x7B8220C3, 0x1332FA33, 0xCA110F0E, 0x5C8892B8, 0x29950C2B, 0xC97681EF, 0x68C94EE2, 0xD440A225,
			0xA1D41591, 0xA7C8FD27, 0xF856F1F5, 0xE9FBF80B, 0x9EE4095D, 0x7CD7ABB8, 0x1F724886, 0x5FD2208D,
			0xA11D1645, 0xC52EED06, 0x3A385C49, 0x333B049D, 0xA9D56D35, 0x7A0A1359, 0xD54ACDE5, 0x672F80D8,
			0x650E145C, 0x1D5623B3, 0xC110A6E1, 0x938368C6, 0x7FB204E4, 0x09532FC6, 0x5708B3BE, 0x53775340,
			0x7945CBF2, 0xAE4B3ED8, 0x4A032DE2, 0x732D0BBA, 0x30124CF7, 0xCE34059F, 0x3B725A0B, 0x0A11D858,
			0x04D0C266, 0xCA5A8CFD, 0x11596B89, 0xDEBEBD47, 0x904727C3, 0x8348E80B, 0x96821CF4, 0xC6E38043,
			0x8DD91C81, 0xF7486116, 0xAD9AB173, 0x55F94456, 0x39B8ADFD, 0x9D0844DB, 0x5B0E5DDB, 0x533BB734,
			0x271F68AB, 0x41DE71A7, 0x111BE94E, 0x4146E77A, 0x9FA4A8D0, 0xC5CC2387, 0xAA52ECD0, 0xD5788D9A,
			0xA0E22D23, 0xF915F1AC, 0x87A85298, 0xD3357D1C, 0x8F73B716, 0x2F999C00, 0xABAD8AEA, 0x6C27A8E3,
			0x4C4E24C1, 0x6DCE6EB8, 0xBDD584B7, 0x3A3A72C2, 0x62347533, 0xF17882C9, 0x4B6F9EB0, 0x53BEBAA5,
			0xB32E36BF, 0x7BC3BC7E, 0x6266B6E6, 0xADB3E8E7, 0xBD83F6B2, 0x75105FAC, 0xDA42A27A, 0xAB1A895B,
			0xBDD7717D, 0x00EBB19C, 0x18A128DF, 0x0141707A, 0xEA8A050C, 0x156D1B72, 0x48C77B38, 0x1D5D1557,
			0xF53CC0C9, 0x3E82CC31, 0x77C96BC6, 0xE7EFAC58, 0xF7941878, 0x7899B1AA, 0x92A0E21C, 0x6CBA87E3,
			0xA0308E83, 0xF45D27B3, 0x4D58DCFF, 0x4A3C05B4, 0x5AAB0446, 0x7FEA3DCA, 0x3406CDAE, 0x6871DADD,
			0x2E4E54FD, 0x893D066F, 0x2D59156E, 0xBC0EC30D, 0x5B51F85D, 0xA29FFC07, 0x27103C0A, 0x85E5810B,
			0xC4B59B82, 0x8192E374, 0x3EE784CA, 0x8205B9C6, 0x710A1BEA, 0x2074CC30, 0x157A012A, 0x1BAC6E0E,
			0x69917FD6, 0xB7B71C77, 0xF72A68D1, 0xE3CBB537, 0x18F43434, 0xB503F818, 0x4CE7CF6C, 0x13F0825A,
			0xC0321868, 0x17ADBC21, 0xAEACD351, 0x71C9634F, 0x1210ED55, 0xFB1873F2, 0x1142E2C1, 0xC7FD983C,
			0x3501708E, 0xB78244AF, 0x6D12AE9B, 0x33A5C535, 0x848307DE, 0x9FD26D52, 0x0B28128F, 0x66467D9D
		};
		private static readonly UInt32[] S2 = {
			0x7714889C, 0xF89F95D0, 0x8ECC344E, 0xFC7540A8, 0x554A4BC4, 0x8B2043C2, 0x7435B4B8, 0xCBEC7455,
			0x7A338AE7, 0xA722D039, 0x1C742F9F, 0xB1464062, 0xF0A9DF6E, 0xD65CB1D2, 0x0F919952, 0xFBC98467,
			0x0B967439, 0xE29503F3, 0xFE167E67, 0xF577DD70, 0x0EA52CDC, 0x68EDA9CD, 0xE2C1DC64, 0x6D97D236,
			0xBF130C5E, 0x66ECFA14, 0xE975303D, 0x8F179292, 0x778E5DD7, 0x54EE304C, 0xD1E0ED71, 0x4756651B,
			0x4BA50714, 0x754BF42C, 0x10EB073B, 0x11C22C25, 0xBC4DB468, 0xD9A248C2, 0x2519BA88, 0x175C8781,
			0xE60FCB43, 0xB4356D85, 0x207A4177, 0x0D159399, 0x153B3062, 0x0D146A37, 0x3F6E7071, 0xE6094AE9,
			0x3C25C9BE, 0x7FB521E2, 0x12B960B2, 0x29A175D8, 0x6C4016B7, 0xB94AE5F9, 0x0FD38E53, 0xE2510506,
			0x61D42700, 0x3141555B, 0x05B2B80E, 0x0D72792B, 0xA7580C76, 0x8E5E2AF7, 0xD219883D, 0x455D66D4,
			0xF532B238, 0x91626823, 0x54BCC490, 0xA16D1718, 0xE99DA5E6, 0xC25CC982, 0x749183B8, 0x18889CC6,
			0xCF68BC7E, 0x7190030C, 0x9C97A738, 0x47367A55, 0x2E34A198, 0xF997D250, 0xAE1633FC, 0xFBC24D44,
			0x4CC604E9, 0x4A6DB903, 0x0BF3E539, 0x739866E1, 0x54EBE56B, 0x3ADC761D, 0x5A80B9F1, 0x828308B4,
			0x234A447E, 0x4A57DE7A, 0xEEAD8A52, 0x5E706632, 0xEF7439AA, 0x4B40F4FF, 0x2A5BB650, 0x78492E1D,
			0xE62DAE10, 0x5F08CA34, 0x979E2724, 0x541AB037, 0x57E854F7, 0x18083290, 0xD2F3EA6B, 0x835E53E7,
			0xB43EE8A3, 0xB729D403, 0xB68995B0, 0x3A19593D, 0x5C705B12, 0x6635A717, 0xDF02C304, 0xDBB60EC4,
			0xB7D56959, 0x5989C1BD, 0x53FA3125, 0x180D03BE, 0xAF099607, 0x23199C31, 0x50CA488C, 0x9BAB3B5D,
			0x8814ED0A, 0x98C49BBF, 0xA21B53AB, 0x7623FD9A, 0x9F921107, 0xC23F4ECB, 0xA5595C80, 0xC96B9A89,
			0x7A817358, 0x5B3123BD, 0x0C4B1D12, 0x678ABE0C, 0x54C2A141, 0xCB85D689, 0x775EBA93, 0xC35293ED,
			0xD389F09C, 0x408F19C7, 0x4F63B7AE, 0xB8DE93C1, 0x5C8D5E85, 0x36DC656C, 0x2097B236, 0x3430E5E5,
			0xBBEBB059, 0x4F12CB48, 0x1639B7E5, 0x5EEF7173, 0xDD86E39D, 0x46AA0831, 0x9A270E68, 0x97180892,
			0x3B8CEB76, 0x03D6629F, 0x28387633, 0x8B83C2A5, 0x4ECDD2CE, 0xC2517456, 0x5B2A0C29, 0x092FA44F,
			0xD56BECE5, 0xC48C79D7, 0x1537DEF2, 0x088AB573, 0xEA120B69, 0x2E29020F, 0x92F1D02D, 0x42F63B42,
			0x88109F63, 0x14B898FE, 0x92053D7D, 0xB417AEDE, 0xF0DDEAD0, 0x0BF392E7, 0xFF57DE49, 0xC422C334,
			0xD5EAF945, 0x76117D1C, 0x7493E5F9, 0x89CE08CD, 0xF3E955B1, 0x684E8AFE, 0x48129654, 0xCB315D7F,
			0xE2577A33, 0x26BA0B20, 0xADE7E8E3, 0xFFCB9785, 0x16501201, 0x37DFEA4D, 0xC6F5EA18, 0x15064DBF,
			0x7C973CCB, 0x9D0582F8, 0x8B1CDF92, 0x62A04738, 0x7904E83E, 0xDDA1A910, 0xAD93AEEA, 0x225DD14F,
			0xED1F770A, 0x87035455, 0x943CA8AD, 0x90E4BBF0, 0x8E1A4159, 0xAED69488, 0xA1B2E865, 0xBBAAD5B8,
			0x0658F48B, 0x1FAB64D8, 0x0E56350E, 0xA11BEE93, 0x74D5E32E, 0x68919CAE, 0x89CF8D33, 0x13C1276A,
			0xB345392B, 0x19A4299F, 0x2BEBAC00, 0xDD035E25, 0x05F63B19, 0x03F7C6FC, 0xF31D04BC, 0xFE393E7C,
			0x0876018A, 0x229617B3, 0xACDFAA1B, 0xAC61CA42, 0x60BFCBCD, 0x1261885C, 0x30D24A1B, 0x623BD13E,
			0xCBFBECF3, 0xD2D0EC61, 0xDD90C430, 0xE736D69B, 0xD8D05CA8, 0x19EFB299, 0xCD34C192, 0xD7DC45C6,
			0xF7274458, 0x74E226CB, 0x04665779, 0xCE257B71, 0xD9BD0BE3, 0x38EB9B67, 0x376E9169, 0x1B2C4AEE,
			0x38A7F1E9, 0xBB87E7CB, 0x950B9FFE, 0x705F345F, 0x044CB99B, 0x92A71C6F, 0x60738A0D, 0x3B197EFC
		};
		private static readonly UInt32[] S3 = {
			0x5645F1DC, 0x5CAD09A5, 0xCFE62DA6, 0x16FAF4ED, 0x3ED8F473, 0x53F17FA6, 0x71A0D777, 0x0F12D82B,
			0x3370A419, 0xA6BA3661, 0xED2573F5, 0x59AD4B0B, 0xABB9DA59, 0x548087BF, 0xD6B446A1, 0x3CB4E9E8,
			0x5B5B13F5, 0xEEDEF32C, 0x825EF7A8, 0x4301BCA0, 0x1EC53D4A, 0x448CB0C1, 0xC16C2D0A, 0x8DDE3BD7,
			0x102E3586, 0x1D6CAE03, 0x68227782, 0x501A5810, 0x3F16036B, 0xEF6B4CEE, 0xE00F9C1B, 0xFC173265,
			0x7CC97E7E, 0x3EE8405D, 0x67ACB0CA, 0x248FF385, 0x93CF276E, 0x134AD39E, 0x5EEEE4B5, 0xBCBB0B32,
			0xFDFBD53B, 0xA44111A5, 0x0AF4EFD7, 0x3D5DFD49, 0xC4C94667, 0xC91564DF, 0x9C07085D, 0x6657452D,
			0xC90E612A, 0xBD536775, 0x34A4C293, 0x1C4D862E, 0xDA74353D, 0xC8B33BAA, 0xCE45E538, 0xCED3CFA2,
			0x8D0A3D8F, 0x3B33DAA2, 0x16771D35, 0x597C44B4, 0x1CA0FD49, 0x8FBF0213, 0x46AADF5A, 0x543DCBD1,
			0xF7B4C368, 0xF8DF0296, 0xB0013FB8, 0xCBD32B54, 0x9CB09DC7, 0xCCA05166, 0x3ACEBD3C, 0xA23F0962,
			0x378D8C7F, 0xEF2F4A76, 0x831E0D5B, 0xC4F49F35, 0x34A0F307, 0x7BA90715, 0xC690AF30, 0xBB09FDC1,
			0x44DDF6D7, 0xEED65794, 0xB05395DB, 0x8C46FDB3, 0xE787F4BE, 0xC5F976D0, 0x48D2F517, 0x07E0B2DD,
			0x521B0A04, 0x2B8E3504, 0x46572E52, 0x4CCB5970, 0xE270188E, 0xA9E9B347, 0x1D8B0CCD, 0xCD9CD8F4,
			0x41D035D0, 0x1F996184, 0xF9093D7E, 0xE248EB56, 0xF76F9A86, 0xE42A1D0C, 0xD29661B1, 0x29B238D3,
			0x474B83A6, 0xC2158B17, 0x99CB9889, 0xF9596E61, 0x2AC2137B, 0xE61321BA, 0x135F8FCD, 0xBE576FF9,
			0xA082F1AA, 0x48F5D8F0, 0xA9FE4177, 0x4F9132DA, 0x06FD550D, 0xBF0E20E6, 0x092EF688, 0xB496F8DD,
			0xDDFC7FD0, 0x50F1FE7D, 0xC7ABFE89, 0xB7575822, 0x122AC856, 0xAA34339F, 0x86AAED3D, 0x1B00A33E,
			0xCAC9E138, 0x3B579DA4, 0x8B2722C2, 0x73A43A42, 0x68190AB5, 0x934A1DD4, 0x181DA997, 0xF07B1309,
			0xD042D970, 0x362BF7DE, 0x3DE2A5C9, 0x3CB769CE, 0x0F7DBB96, 0x169CD10E, 0x38702FEE, 0x45417E56,
			0xEF9D8F64, 0x3E6EA751, 0x757C3593, 0xA7DF968A, 0x9F93D443, 0x72A7F8DF, 0x6F66D026, 0x0C542EAD,
			0x3602F34F, 0xAC58FED6, 0xD40D9FFA, 0xC776C078, 0x5A477507, 0xB6CF460A, 0x416C99EF, 0x4910EA60,
			0x8A638E6F, 0x4C91CE3D, 0x401D9528, 0xA277DEFF, 0xAD47C250, 0x5A9AEF86, 0x599FCE52, 0xD4FBAB34,
			0x9FFCA4B2, 0xDAD4D731, 0x668E5D15, 0x4FE585D5, 0x7832CB02, 0xF727216C, 0xDAA27423, 0xA60F17BD,
			0xC9A83FB4, 0x0206C82A, 0xA38F1593, 0xF6A8E75D, 0x096581BB, 0xEE93E13D, 0xFB763F80, 0x5FF4D818,
			0x851BF706, 0xD2E6187E, 0x23EA4E4D, 0x41EFD306, 0x1C5B961B, 0x6F80D114, 0x4AF73888, 0x34A7749D,
			0xE54A20DB, 0x0196E64A, 0x1B35DD37, 0x53D323FE, 0xD7774720, 0x77DEA9F2, 0x02AF4FE7, 0xF708E38C,
			0x43D839C8, 0xF3B50139, 0x0317EA3C, 0x94599685, 0x3E6C987D, 0x29CE96B5, 0x7255B6CA, 0x9311017A,
			0x90006555, 0x8EE0DBCE, 0x2B340269, 0x9B9D87B4, 0xB66AE833, 0x23264CDE, 0x65A382F6, 0x55D04305,
			0x799B0361, 0xD0DFA8CF, 0xB8321CB7, 0x0F96E89F, 0xE75243E6, 0x56E34DAA, 0xF7DC59F0, 0xC6A254C1,
			0x20763142, 0xAADE08C5, 0xB0FBE9F6, 0x9814F814, 0xC243A991, 0x63240C41, 0x2DB95B91, 0xE32E3ECE,
			0x71D58323, 0xC4099A63, 0xF4121B9F, 0xFF6A92DE, 0xA464009F, 0xBCE7D473, 0x59C7FE25, 0x966BCD3B,
			0x6745374B, 0xA999BE39, 0xA7A1A03F, 0xFA4F35C7, 0x4E9434F5, 0x63DA2689, 0x61DD5505, 0x82D7DF35,
			0x47CD296B, 0x54E43C84, 0x3ACC01E3, 0x2728436C, 0xB6E4E751, 0xFDE73E2D, 0x61FD1F03, 0x80B1896C
		};
		private static readonly UInt32[] S4 = {
			0xF018C293, 0x5520254E, 0x6CF078AE, 0xC2D125C4, 0xCF1ACD98, 0xE455BCC0, 0xBC0C78D9, 0xFBEA64B0,
			0xD936BAC7, 0x9D25EDD6, 0x88438A2C, 0x388A9897, 0x3FDCD819, 0x15A9D3B5, 0x88DCF892, 0x9E1869A1,
			0x05E31DED, 0x23551C7B, 0x09697218, 0x3C032283, 0x50959570, 0x46213323, 0xAA02CA0D, 0xB830F2F3,
			0x23BE9E0A, 0xE6A5F457, 0x8B171EAE, 0x21FE5DF8, 0x66C54579, 0xAE38741F, 0x116010C1, 0x6022599D,
			0xB87F4269, 0x193013E7, 0xE1212A2D, 0x2ABCC493, 0x01234423, 0x1709D99C, 0x1A8BBD5A, 0xF9325A68,
			0xF62C0C4C, 0x33C3AFD0, 0x0C684E8D, 0xDB7F67CC, 0x10D407AB, 0x7D558109, 0x578290EF, 0xA03249E7,
			0xD42FC90B, 0x7867B3AA, 0x0BDB6DD8, 0x7CD48EB7, 0x4DD920CA, 0xC364E5B9, 0xBB585D8C, 0x9450440B,
			0x41EA48FC, 0x98AB7799, 0xBE31EA4B, 0x613CE8D2, 0xEB3ED9F2, 0x0083AD22, 0xBAB1B914, 0xD1C2FBC9,
			0x89A1D8CC, 0xC70467AF, 0x0C3392FC, 0x7BD8368F, 0xBB629FC0, 0xEDF9B8C6, 0x575C6A56, 0xC1F1B1F9,
			0xC2379422, 0xC48248F4, 0x554B5238, 0x26CD820B, 0xAEF07260, 0xB34F7109, 0xF0A3C827, 0x6EB63659,
			0x35EEFE00, 0x07B76B6A, 0x1D85EDA6, 0xB4E09877, 0x9A1B38F1, 0x022E1E43, 0xEFA5C431, 0x365869D8,
			0x533240E8, 0x47646472, 0x4E3FF530, 0x92E7A796, 0xC33B382C, 0x66E401B8, 0x068268D8, 0x351356F5,
			0x2B856BB8, 0x41728B86, 0x29118F33, 0xB1012747, 0x360DA39A, 0x5799B554, 0xAE2F7B14, 0x06142458,
			0x176023B4, 0x0B232299, 0x7F9424DE, 0xE6DF6977, 0x1594036D, 0xD8C1DA2C, 0x39ABC777, 0xBA765584,
			0x806AD233, 0x4B6DD1F0, 0x5376BCE2, 0xCF4C2CF0, 0x4D2D3AEB, 0x1816DEA3, 0x5456DE6F, 0x4DCD2B1F,
			0x8A5E4329, 0x850063B0, 0x3A6D3D3D, 0x6454C3B5, 0x99C304BB, 0x3F57A56F, 0x4ECB37CD, 0x02EFAF48,
			0x55DB1A97, 0xB4778B39, 0xE2084781, 0xE42D7C9B, 0x2F245B98, 0xD9C7931C, 0x879A06A4, 0x01E4C305,
			0x44AFF51B, 0xD573C5CB, 0x35EB0F59, 0x5836AEBA, 0xDB25F1A4, 0xB7E3DFAC, 0xEB5C118A, 0xF906710A,
			0x4D6F843C, 0x9CAD016A, 0x8A869652, 0xEAAA9A0E, 0xF7AB07A4, 0x0918EDB8, 0x5A89572A, 0xEF969C0E,
			0x3189B0F1, 0x10F28E86, 0xEEFC3BA0, 0x56AE1DD2, 0xCF4E215D, 0xD26F4635, 0x7BE91E8B, 0x484C7682,
			0x5832BF16, 0x431B617A, 0x72A70A01, 0xE0643497, 0x293A4557, 0xD06AC8DA, 0xB91A7C38, 0x9A8C975A,
			0xBB284A71, 0x9AFC3CF5, 0x0F8E3E29, 0x6EF16E2E, 0x355ED02F, 0x04ADE3B4, 0x618397DD, 0x4896E3BA,
			0x4E09A5AF, 0x6A705619, 0x362FB1B0, 0x7C1267C0, 0x248E59E0, 0x1750EE5B, 0x0EEF5BF8, 0x614F2C39,
			0x2D9D1811, 0x773A4773, 0xB7A127C4, 0x5E538C89, 0x2FCC7DFF, 0xB19F602C, 0x7D00CBA7, 0x83CBE563,
			0xCBC1A7F3, 0xBA0302D4, 0xD0A0A9AD, 0x625E4DF6, 0x375A4179, 0x9DC68CB5, 0x012564A3, 0x941B743A,
			0x137616EA, 0x5CDD52F2, 0xED32B46D, 0x52977BF7, 0xB04892E3, 0xD74590B9, 0x7294A4A9, 0x5A8A6CE8,
			0x525C6872, 0xF2D75A33, 0x73D8C8AF, 0xDD674809, 0x4BADFB68, 0x83188C00, 0xF5A69645, 0xEA11C451,
			0x7A0C3DD7, 0xE5230B3D, 0xA086BA9B, 0x7631022B, 0x8E2D757A, 0xE8285DA3, 0xD21F99FA, 0x6E061D25,
			0x9434C2AD, 0xD34FD8D3, 0xA9FFC56F, 0xA8E43BFA, 0x1616DD33, 0x60D01570, 0x35E72B7A, 0xF35F5829,
			0x1A04CC2A, 0xB2F918A1, 0x051FE85E, 0x3140C1EC, 0x0D43BF3A, 0x2CADA881, 0x74367CA0, 0x9C5E2753,
			0x7A77C4A0, 0x20C9B9B0, 0xE5A8F796, 0x5A2B88FF, 0x42094808, 0xD79339FB, 0x4469CC37, 0xEC46A5B6,
			0x96BDE46D, 0x5B9AD485, 0xAEFB240D, 0xFE750F70, 0xFF7C29EC, 0x39FCD6CE, 0xEB63DB22, 0x77A784EB
		};

		private static UInt32 F( UInt32 input ) {
			return
				((S1[input >> 24]
				+ S2[input >> 16 & 0xff])
				^ S3[input >> 8 & 0xff])
				+ S4[input & 0xff];
		}

		public static void Decrypt( Byte[] data ) {
			for ( int i = 0 ; i < data.Length ; i += 8 ) {
				UInt32 L = BitConverter.ToUInt32(data, i);
				UInt32 R = BitConverter.ToUInt32(data, i + 4);

				for ( int r = 16 ; r > 0 ; r -= 2 ) {
					L ^= P[r + 1];
					R ^= F(L);
					R ^= P[r];
					L ^= F(R);
				}
				L ^= P[1];
				R ^= P[0];

				UInt32 TMP = L;
				L = R;
				R = TMP;
				
				Buffer.BlockCopy(BitConverter.GetBytes(L), 0, data, i, 4);
				Buffer.BlockCopy(BitConverter.GetBytes(R), 0, data, i+4, 4);
			}
		}
		public static void Encrypt( Byte[] data ) {
			for ( int i = 0 ; i < data.Length ; i += 8 ) {
				UInt32 L = BitConverter.ToUInt32(data, i);
				UInt32 R = BitConverter.ToUInt32(data, i + 4);

				for ( int r = 0 ; r < 16 ; r += 2 ) {
					L ^= P[r];
					R ^= F(L);
					R ^= P[r + 1];
					L ^= F(R);
				}
				L ^= P[16];
				R ^= P[17];

				UInt32 TMP = L;
				L = R;
				R = TMP;

				Buffer.BlockCopy(BitConverter.GetBytes(L), 0, data, i, 4);
				Buffer.BlockCopy(BitConverter.GetBytes(R), 0, data, i+4, 4);
			}
		}
	}

    public static class MHWCrypto {
		public static void DecryptCharacter ( Byte[] save, UInt32 offset ) {
			RijndaelManaged aes = new RijndaelManaged() {
				Mode = CipherMode.ECB,
				Padding = PaddingMode.None
			};
			
			UInt32 keySalt = Crc32(0xA37A55D7, save, offset + 0x2098C0, 0x200);

			Byte[] salt = new Byte[0x200]; {
				UInt32 c = keySalt ^ 0x4BF0CF23;
				UInt32 saltInt = 0;
				UInt32 o = 0x5D7;
				UInt32 od = (keySalt >> 0x18) + (keySalt >> 0x10 & 0xFF) + (keySalt >> 0x8 & 0xFF) + (keySalt & 0xFF) + 1;
				for ( UInt32 i = 0 ; i < 0x200 ; i += 4, o += od ) {
					saltInt = CONST_TABLE_UINT32[o & 0xFFF] ^ c;
					if ( (saltInt & 0x7) == 1 )
						saltInt ^= 0xBD75F29;

					salt[i] = (Byte) saltInt;
					salt[i + 1] = (Byte) (saltInt >> 0x8);
					salt[i + 2] = (Byte) (saltInt >> 0x10);
					salt[i + 3] = (Byte) (saltInt >> 0x18);
				}
			}

			Byte ks1 = (Byte) keySalt;
			Byte ks2 = (Byte) (keySalt >> 0x8);
			Byte ks3 = (Byte) (keySalt >> 0x10);
			Byte ks4 = (Byte) (keySalt >> 0x18);

			UInt32 roundOffset = offset;
			for ( UInt32 r = 0 ; r < 32 ; ++r ) {
				Byte[] roundKey = new Byte[16];	{
					Byte e1 = salt[4 * r    ];
					Byte e2 = salt[4 * r + 1];
					Byte e3 = salt[4 * r + 2];
					Byte e4 = salt[4 * r + 3];

					roundKey[ 0] = (Byte) (e1 ^ 0xA9 ^ ks1);
					roundKey[ 1] = (Byte) (e2 ^ 0x79 ^ ks2);
					roundKey[ 2] = (Byte) (e3 ^ 0x8B ^ ks3);
					roundKey[ 3] = (Byte) (e4 ^ 0x5A ^ ks4);
					roundKey[ 4] = (Byte) (e1 ^ 0x90 ^ ks1);
					roundKey[ 5] = (Byte) (e2 ^ 0x6F ^ ks2);
					roundKey[ 6] = (Byte) (e3 ^ 0x61 ^ ks3);
					roundKey[ 7] = (Byte) (e4 ^ 0x34 ^ ks4);
					roundKey[ 8] = (Byte) (e1 ^ 0xDF ^ ks1);
					roundKey[ 9] = (Byte) (e2 ^ 0x38 ^ ks2);
					roundKey[10] = (Byte) (e3 ^ 0xC6 ^ ks3);
					roundKey[11] = (Byte) (e4 ^ 0xC4 ^ ks4);
					roundKey[12] = (Byte) (e1 ^ 0xE8 ^ ks1);
					roundKey[13] = (Byte) (e2 ^ 0x64 ^ ks2);
					roundKey[14] = (Byte) (e3 ^ 0xFB ^ ks3);
					roundKey[15] = (Byte) (e4 ^ 0x94 ^ ks4);
				}
				aes.Key = roundKey;
				ICryptoTransform decryptor = aes.CreateDecryptor();

				UInt32 roundThreshold = (UInt32) ((r + 1) * 0x104C6 + (Int32) (0x104C6 * (CONST_TABLE_SINGLE[CONST_TABLE_UINT32[(keySalt + r) & 0xFFF ^ 0x5d7] & 0xFFF ^ 0x885] - 0.5F)) + 0xF & 0xFFFFFFF0);
				if ( r == 31 )
					roundThreshold = 0x2098C0;

				for ( UInt32 i = 0, j = 0 ; roundOffset + i < offset + roundThreshold ; i += 16, j += 4 ) {
					if ( (salt[j & 0x1FF] & 1) == 0 ) {
						save[roundOffset + i     ] ^= salt[j +  8 & 0x1FF];
						save[roundOffset + i +  1] ^= salt[j +  9 & 0x1FF];
						save[roundOffset + i +  2] ^= salt[j + 10 & 0x1FF];
						save[roundOffset + i +  3] ^= salt[j + 11 & 0x1FF];
						save[roundOffset + i +  8] ^= salt[j + 12 & 0x1FF];
						save[roundOffset + i +  9] ^= salt[j + 13 & 0x1FF];
						save[roundOffset + i + 10] ^= salt[j + 14 & 0x1FF];
						save[roundOffset + i + 11] ^= salt[j + 15 & 0x1FF];

						decryptor.TransformBlock(save, (Int32) (roundOffset + i), 16, save, (Int32) (roundOffset + i));

						save[roundOffset + i +  4] ^= salt[j      & 0x1FF];
						save[roundOffset + i +  5] ^= salt[j +  1 & 0x1FF];
						save[roundOffset + i +  6] ^= salt[j +  2 & 0x1FF];
						save[roundOffset + i +  7] ^= salt[j +  3 & 0x1FF];
						save[roundOffset + i + 12] ^= salt[j +  4 & 0x1FF];
						save[roundOffset + i + 13] ^= salt[j +  5 & 0x1FF];
						save[roundOffset + i + 14] ^= salt[j +  6 & 0x1FF];
						save[roundOffset + i + 15] ^= salt[j +  7 & 0x1FF];
					} else {
						save[roundOffset + i +  4] ^= salt[j +  8 & 0x1FF];
						save[roundOffset + i +  5] ^= salt[j +  9 & 0x1FF];
						save[roundOffset + i +  6] ^= salt[j + 10 & 0x1FF];
						save[roundOffset + i +  7] ^= salt[j + 11 & 0x1FF];
						save[roundOffset + i + 12] ^= salt[j + 12 & 0x1FF];
						save[roundOffset + i + 13] ^= salt[j + 13 & 0x1FF];
						save[roundOffset + i + 14] ^= salt[j + 14 & 0x1FF];
						save[roundOffset + i + 15] ^= salt[j + 15 & 0x1FF];

						decryptor.TransformBlock(save, (Int32) (roundOffset + i), 16, save, (Int32) (roundOffset + i));

						save[roundOffset + i     ] ^= salt[j      & 0x1FF];
						save[roundOffset + i +  1] ^= salt[j +  1 & 0x1FF];
						save[roundOffset + i +  2] ^= salt[j +  2 & 0x1FF];
						save[roundOffset + i +  3] ^= salt[j +  3 & 0x1FF];
						save[roundOffset + i +  8] ^= salt[j +  4 & 0x1FF];
						save[roundOffset + i +  9] ^= salt[j +  5 & 0x1FF];
						save[roundOffset + i + 10] ^= salt[j +  6 & 0x1FF];
						save[roundOffset + i + 11] ^= salt[j +  7 & 0x1FF];
					}
				}
				roundOffset = offset + roundThreshold;
			}
		}
        public static void EncryptCharacter ( Byte[] save, UInt32 offset ) {
            RijndaelManaged aes = new RijndaelManaged() {
				Mode = CipherMode.ECB,
				Padding = PaddingMode.None
			};

            UInt32 keySalt = Crc32(0xA37A55D7, save, offset + 0x2098C0, 0x200);
            
            Byte[] salt = new Byte[0x200]; {
				UInt32 c = keySalt ^ 0x4BF0CF23;
				UInt32 saltInt = 0;
				UInt32 o = 0x5D7;
				UInt32 od = (keySalt >> 0x18) + (keySalt >> 0x10 & 0xFF) + (keySalt >> 0x8 & 0xFF) + (keySalt & 0xFF) + 1;
				for ( UInt32 i = 0 ; i < 0x200 ; i += 4, o += od ) {
					saltInt = CONST_TABLE_UINT32[o & 0xFFF] ^ c;
					if ((saltInt & 0x7) == 1)
						saltInt ^= 0xBD75F29;

					salt[i] = (Byte)saltInt;
					salt[i + 1] = (Byte)(saltInt >> 0x8);
					salt[i + 2] = (Byte)(saltInt >> 0x10);
					salt[i + 3] = (Byte) (saltInt >> 0x18);
				}
			}

			Byte ks1 = (Byte) keySalt;
			Byte ks2 = (Byte)(keySalt >> 0x8);
			Byte ks3 = (Byte)(keySalt >> 0x10);
			Byte ks4 = (Byte)(keySalt >> 0x18);

			UInt32 roundOffset = offset;
            for (UInt32 r = 0; r < 32; ++r) {
				Byte[] roundKey = new Byte[16]; {
					Byte e1 = salt[4 * r    ];
					Byte e2 = salt[4 * r + 1];
					Byte e3 = salt[4 * r + 2];
					Byte e4 = salt[4 * r + 3];

					roundKey[ 0] = (Byte)(e1 ^ 0xA9 ^ ks1);
					roundKey[ 1] = (Byte)(e2 ^ 0x79 ^ ks2);
					roundKey[ 2] = (Byte)(e3 ^ 0x8B ^ ks3);
					roundKey[ 3] = (Byte)(e4 ^ 0x5A ^ ks4);
					roundKey[ 4] = (Byte)(e1 ^ 0x90 ^ ks1);
					roundKey[ 5] = (Byte)(e2 ^ 0x6F ^ ks2);
					roundKey[ 6] = (Byte)(e3 ^ 0x61 ^ ks3);
					roundKey[ 7] = (Byte)(e4 ^ 0x34 ^ ks4);
					roundKey[ 8] = (Byte)(e1 ^ 0xDF ^ ks1);
					roundKey[ 9] = (Byte)(e2 ^ 0x38 ^ ks2);
					roundKey[10] = (Byte)(e3 ^ 0xC6 ^ ks3);
					roundKey[11] = (Byte)(e4 ^ 0xC4 ^ ks4);
					roundKey[12] = (Byte)(e1 ^ 0xE8 ^ ks1);
					roundKey[13] = (Byte)(e2 ^ 0x64 ^ ks2);
					roundKey[14] = (Byte)(e3 ^ 0xFB ^ ks3);
					roundKey[15] = (Byte)(e4 ^ 0x94 ^ ks4);
				}
                aes.Key = roundKey;
                ICryptoTransform encryptor = aes.CreateEncryptor();

				UInt32 roundThreshold = (UInt32) ((r + 1) * 0x104C6 + (Int32) (0x104C6 * (CONST_TABLE_SINGLE[CONST_TABLE_UINT32[(keySalt + r) & 0xFFF ^ 0x5d7] & 0xFFF ^ 0x885] - 0.5F)) + 0xF & 0xFFFFFFF0);
				if ( r == 31 )
					roundThreshold = 0x2098C0;

				for ( UInt32 i = 0, j = 0 ; roundOffset + i < offset + roundThreshold ; i += 16, j += 4 ) {
					if ( (salt[j & 0x1FF] & 1) == 0 ) {
						save[roundOffset + i +  4] ^= salt[j      & 0x1FF];
						save[roundOffset + i +  5] ^= salt[j +  1 & 0x1FF];
						save[roundOffset + i +  6] ^= salt[j +  2 & 0x1FF];
						save[roundOffset + i +  7] ^= salt[j +  3 & 0x1FF];
						save[roundOffset + i + 12] ^= salt[j +  4 & 0x1FF];
						save[roundOffset + i + 13] ^= salt[j +  5 & 0x1FF];
						save[roundOffset + i + 14] ^= salt[j +  6 & 0x1FF];
						save[roundOffset + i + 15] ^= salt[j +  7 & 0x1FF];

						encryptor.TransformBlock(save, (Int32) (roundOffset + i), 16, save, (Int32) (roundOffset + i));

						save[roundOffset + i     ] ^= salt[j +  8 & 0x1FF];
						save[roundOffset + i +  1] ^= salt[j +  9 & 0x1FF];
						save[roundOffset + i +  2] ^= salt[j + 10 & 0x1FF];
						save[roundOffset + i +  3] ^= salt[j + 11 & 0x1FF];
						save[roundOffset + i +  8] ^= salt[j + 12 & 0x1FF];
						save[roundOffset + i +  9] ^= salt[j + 13 & 0x1FF];
						save[roundOffset + i + 10] ^= salt[j + 14 & 0x1FF];
						save[roundOffset + i + 11] ^= salt[j + 15 & 0x1FF];
					} else {
						save[roundOffset + i     ] ^= salt[j      & 0x1FF];
						save[roundOffset + i +  1] ^= salt[j +  1 & 0x1FF];
						save[roundOffset + i +  2] ^= salt[j +  2 & 0x1FF];
						save[roundOffset + i +  3] ^= salt[j +  3 & 0x1FF];
						save[roundOffset + i +  8] ^= salt[j +  4 & 0x1FF];
						save[roundOffset + i +  9] ^= salt[j +  5 & 0x1FF];
						save[roundOffset + i + 10] ^= salt[j +  6 & 0x1FF];
						save[roundOffset + i + 11] ^= salt[j +  7 & 0x1FF];

						encryptor.TransformBlock(save, (Int32) (roundOffset + i), 16, save, (Int32) (roundOffset + i));

						save[roundOffset + i +  4] ^= salt[j +  8 & 0x1FF];
						save[roundOffset + i +  5] ^= salt[j +  9 & 0x1FF];
						save[roundOffset + i +  6] ^= salt[j + 10 & 0x1FF];
						save[roundOffset + i +  7] ^= salt[j + 11 & 0x1FF];
						save[roundOffset + i + 12] ^= salt[j + 12 & 0x1FF];
						save[roundOffset + i + 13] ^= salt[j + 13 & 0x1FF];
						save[roundOffset + i + 14] ^= salt[j + 14 & 0x1FF];
						save[roundOffset + i + 15] ^= salt[j + 15 & 0x1FF];
					}
				}
				roundOffset = offset + roundThreshold;
            }
        }
		
		public static void PrintByteArray(byte[] bytes)
		{
			var sb = new StringBuilder();
			foreach (var b in bytes)
				sb.Append($"{b:X02}");
			Console.WriteLine(sb.ToString());
		}
		public static Byte[] GenerateChecksumCharacter0 ( Byte[] data ) {
			Console.WriteLine("Character checksum 0");
			Byte[] current = new Byte[0x200];
			Buffer.BlockCopy(data, 0x3010D8+0x2098C0, current, 0, 0x200);
			Byte[] gen = GenerateSaveSlotChecksum(data, 0x3010D8, 0x2098C0, 0);
			PrintByteArray(current);
			PrintByteArray(gen);
			return gen;
        }

		private static byte[] GenerateSaveSlotChecksum(byte[] data, int offset, int length, int saveSlot)
        {
            byte[] checksum = new byte[0x200];
            uint[] constants = { 0x55012174, 0x9FA3690, 0x4F5AE762, 0xA37A55D7 };
            int[] slotConstantsGenerator = { 0x2EA10CEB, 0x204DE35E, 0x4BF0CF23, 0x72B401FD, 0x5CDD1F19, 0x681BA6CF, 0x626B4CA, 0x7C8B3AF0 };
            int lengthInt = length >> 3;

            int[] hashLookup = new int[8];
            int[] partialCrcs = new int[8];
            int[] crcLengths = new int[8];
            int[] slotConstants = new int[8];

            for (int i = 0; i < 8; ++i)
            {
                slotConstants[i] = (int)(slotConstantsGenerator[i] ^ constants[-saveSlot - i - 1 & 3]);
            }

            for (int i = 0; i < 7; ++i)
            {
                float variation = CONST_TABLE_SINGLE[(slotConstants[i] + CONST_TABLE_UINT32[slotConstants[i] & 0xfff]) & 0xfff];
                crcLengths[i] = (int)((variation - 0.5F) * (float)lengthInt) + (i + 1) * lengthInt;
            }
            crcLengths[7] = length;



            int crcInit = slotConstants[0];
            int currentLength = crcLengths[0];
            for (int i = 0; i < 8; ++i)
            {
                partialCrcs[i] = (int)Crc32((uint)crcInit, data, (uint)offset, (uint)currentLength);
                if (i < 7)
                {
                    offset += currentLength;
                    currentLength = crcLengths[i + 1] - crcLengths[i];
                    crcInit = partialCrcs[i] ^ slotConstants[i + 1];
                }
            }

            for (int i = 0; i < 7; ++i)
            {
                hashLookup[i] = slotConstants[i] ^ partialCrcs[i] ^ partialCrcs[7];
            }
            hashLookup[7] = slotConstants[7] ^ partialCrcs[7];

            int nextIndex = (int)Crc32(Crc32(0xA37A55D7 ^ constants[3 - saveSlot], slotConstants, 0, 8), partialCrcs, 0, 8);
            int currentIndex;
            int jump = (int)((uint)nextIndex >> 24) + (nextIndex >> 16 & 0xFF) + (nextIndex >> 8 & 0xFF) + (nextIndex & 0xFF);
			for ( int i = 0 ; i < 0x200 ; i += 4 ) {
				currentIndex = nextIndex & 0xFFF;
				nextIndex = (nextIndex + jump + 1) & 0xFFF;
				int checksumInt = (int) (CONST_TABLE_UINT32[currentIndex] ^ hashLookup[(CONST_TABLE_UINT32[currentIndex] + saveSlot) & 7]);
				if ( (CONST_TABLE_UINT32[currentIndex] & 0x7) == 1 )
					checksumInt ^= 0xBD75F29;
				checksum[i] = (byte) checksumInt;
				checksum[i + 1] = (byte) (checksumInt >> 0x8);
				checksum[i + 2] = (byte) (checksumInt >> 0x10);
				checksum[i + 3] = (byte) (checksumInt >> 0x18);
			}

            return checksum;
        }

		public static Byte[] GenerateHash ( Byte[] data ) {
			Console.WriteLine("File checksum 0");
			Byte[] current = new Byte[0x14];
			Buffer.BlockCopy(data, 0xC, current, 0, 0x14);
			Byte[] gen;
			using (SHA1Managed sha1 = new SHA1Managed())
				gen = sha1.ComputeHash(data, 64, data.Length - 64);

			Byte tmpi0, tmpi1;
			for (int i = 0; i < gen.Length; i += 4) {
				tmpi0 = gen[i];
				tmpi1 = gen[i + 1];
				gen[i] = gen[i + 3];
				gen[i + 1] = gen[i + 2];
				gen[i + 2] = tmpi1;
				gen[i + 3] = tmpi0;
			}

			PrintByteArray(current);
			PrintByteArray(gen);
			return gen;
        }

        private static UInt32 Crc32(UInt32 iv, Int32[] data, UInt32 offset, UInt32 length) {
            for (UInt32 i = offset; i < offset + length; ++i) {
                for (UInt32 j = 0; j < 4; ++j) {
                    UInt32 temp = (uint)((iv ^ (data[i] >> (Int32)(8 * j))) & 0xFF);

                    for (UInt32 k = 0; k < 8; ++k) {
                        if ((temp & 1) == 1) {
                            temp >>= 1;
                            temp ^= 0xEDB88320;
                        }
                        else
                            temp >>= 1;
                    }

                    iv >>= 8;
                    iv ^= temp;
                }
            }
            return iv;
        }
        private static UInt32 Crc32(UInt32 iv, Byte[] data, UInt32 offset, UInt32 length) {
            for (UInt32 i = offset; i < offset + length; ++i) {
                UInt32 t = (iv ^ data[i]) & 0xFF;

                for (UInt32 j = 0; j < 8; ++j) {
                    if ((t & 1) == 1) {
                        t >>= 1;
                        t ^= 0xEDB88320;
                    }
                    else
                        t >>= 1;
                }

                iv >>= 8;
                iv ^= t;
            }
            return iv;
        }

		private static UInt32[] CONST_TABLE_UINT32 = {
            0xE935AE79, 0x5766EB6D, 0x610CAC54, 0xF482BA5D, 0xEDF65227, 0xC59D7221, 0x9973C2EE, 0xB954C703, 0x511AF53B, 0xE6C418F3, 0xF505B00C, 0x6D63738A, 0xFED58C15, 0x084A75C4, 0xBF219BF5, 0x1697BE71,
			0x70262EE4, 0xD08D28B9, 0xDB70B945, 0x40962861, 0x076597C9, 0x48244D4D, 0x42071403, 0x784E89AE, 0xDF0B0D89, 0x8062C2B7, 0x3226320F, 0xD8041479, 0x1D0DBA31, 0xA8F67913, 0x6D86A770, 0x2A98400D,
            0x89976F71, 0xBBCE0C1D, 0xAF2FAA27, 0x93C2E10C, 0x5F82E3A6, 0x6C3AD1D6, 0x4A69835F, 0x77721213,	0x885C89A1, 0x56334D84, 0x1DDECD44, 0xDE525928, 0xD2C661DA, 0x1A539AC0, 0xE5031EBE, 0x975B3C4D,
			0xCC28DD37, 0x07ECA88C, 0xE338A216, 0x267AC765, 0xDD7E48C5, 0xD5A1CC33, 0x92B104A9, 0x2F446603,	0xDA2159CC, 0x8E85EB0F, 0x4211D5EF, 0xF221CEF3, 0x1058DB37, 0xF564415C, 0xAEE2C9A5, 0x78CD7A39,
            0x83E03693, 0x4B20FF5E, 0x6AD692D2, 0x12086BEC, 0x715191A8, 0xE84C8F0B, 0x8DC36F82, 0x7D73DDBF,	0xF0FC17D6, 0x3D5818BF, 0xFC8A91C1, 0xC5FBA0B7, 0x88879EE7, 0xBD1C7285, 0x79CA6141, 0x18DADF1D,
			0x8A719573, 0xB01FC8D0, 0x448F1FE7, 0x0F045D99, 0x081C6349, 0xA2B8B412, 0xA0A31D41, 0x0142149E,	0x90AFAFE0, 0xA292E4DE, 0x9296E661, 0x8FA6669E, 0x8D4540A3, 0xE386B4E7, 0xD0600DBB, 0xB9C255B3,
            0x81AA6254, 0x6012C262, 0xF4F8FF12, 0xA03E926C, 0x1AC3EBBD, 0x1E4B27DF, 0xAD8F0BDA, 0xDDD607F7,	0x938335AB, 0x615D2B6E, 0x5FA284AE, 0xD74BF313, 0xC80D63A4, 0x9DAE517C, 0x9495E855, 0x79ED3794,
			0x4EC78546, 0x686E74D2, 0xBCE6F6F7, 0xAE593729, 0xF763E742, 0x0ECC1681, 0x4D011B37, 0x76572F39,	0xFD45C887, 0xEE886CC3, 0xBBEA71F5, 0x2A4033C7, 0xD00FC579, 0x1F09027C, 0x3C57D276, 0x320BB91D,
            0x27A28404, 0x8DC5CB33, 0xD1482CD7, 0xD7CC9F93, 0x7F154EDE, 0x20540B72, 0xA59B4A01, 0x4C516598,	0x883038B2, 0xAB4A4504, 0x1965859C, 0x6DF23D84, 0x002B1F33, 0x4DB60B67, 0x95629FB9, 0x73D290F3,
			0x61FE0711, 0xF8648B6C, 0x72222826, 0xB09F8024, 0x9D1810F6, 0x276F31F1, 0xE5F780D7, 0x87B61F10,	0xBB206249, 0x5184B817, 0x477FDFAE, 0xFA320021, 0xDC4019E3, 0xDF98262C, 0x08396C30, 0x555C6F85,
            0x394377AB, 0xF0183A6B, 0x7591A009, 0xD9BCFDBB, 0x59FD6B7F, 0xA9C0CFCB, 0x5464FFEE, 0x8245AA9A,	0xFA1DBBCA, 0x9F6776FD, 0x10F0A4B2, 0x9152DFA6, 0xFDFB0AF9, 0xC9F1DFC2, 0xB3388567, 0x6CECF175,
			0x32D2C790, 0x538E9C07, 0xC18BA8D1, 0xDE5B9D12, 0x955858BF, 0x027AF734, 0xB3B836A7, 0x0F60C5E4,	0x281C2EC1, 0x96F2595A, 0x193AFA28, 0x9C794699, 0xCEF690E0, 0x256E0018, 0x11322F9B, 0x3F0B80C2,
            0xC25A133A, 0xB149D1C4, 0xD8477DFC, 0x9F2F65D8, 0x48146B72, 0xCF50A4E3, 0x0493A923, 0xD3F8EE0D,	0x8FD63F78, 0x1FC3FD0D, 0xFEDC9372, 0x43DC3931, 0x351E397D, 0xE570EC01, 0x63E1A59D, 0x04ED8A69,
			0x5F58DE9F, 0xD611F2E7, 0xE2F83D84, 0x6886816F, 0x3C35F6D4, 0x408E2C53, 0xEE5787D4, 0x08E9E302,	0xDF7850FA, 0xD51A4627, 0xA5B181E2, 0xBD5463D2, 0xBAC132A7, 0x70004DAF, 0x7F6C9580, 0x5E92FC6E,
            0x3717A502, 0x114B469D, 0xAEB5250C, 0x4129E02C, 0xF4419B3A, 0x893C5069, 0x94BA7713, 0x25DFBF23,	0xA6380C50, 0xE73A9174, 0xCC8EAEBE, 0x5749B33B, 0x056A31FB, 0xD9E0A50B, 0xCE9A56D4, 0x90F790A0,
			0x969FB638, 0xF3335D22, 0x9C6FDCD8, 0xA4C76CA3, 0x3D333D88, 0xCE80E260, 0x9791B8A3, 0x83EDF9ED,	0x84617998, 0x1AAB5519, 0x8CCACF20, 0x81B7FDE3, 0xF7CA955A, 0xD758D472, 0x492A3903, 0xAA6EB56F,
            0xF8DC322F, 0xAA9F8630, 0xB5232F66, 0x96D1217D, 0xFA09ACFC, 0x4D5D7F2D, 0xA0749FDC, 0x58D7420C,	0x43DF58FD, 0xC4B8EF3C, 0xBD84561D, 0x068F446B, 0xF473079C, 0x020181C4, 0x61553615, 0x36EF948B,
			0x236FCD15, 0x9EFEC23E, 0xB400F7C2, 0x1D37B355, 0x51D2462A, 0x12F19353, 0x0008FD01, 0xEF13A095,	0x8753A224, 0x6D562872, 0x635E0DC7, 0xD620AA08, 0x13B0C5BB, 0x924D4626, 0x0F2ABB26, 0x9D86D902,
            0x1AF3C420, 0x1C5BB565, 0xA0C6F373, 0xB96FBB21, 0xC3318945, 0x5763B1FC, 0x19269F2C, 0x8D58B7FF,	0x0547CF12, 0xAD012AD6, 0xD95A42EB, 0xD84D1043, 0xBC5CBA38, 0xBCBFA30A, 0x46EE9078, 0x707D5B71,
			0x17DBE043, 0x3C09DE10, 0x9656817E, 0xAC8732FC, 0x9CCD8F6E, 0xB5CF7AC7, 0x289D1534, 0xBC72E4EC,	0x319B2C08, 0xF4847957, 0x4D84BBD0, 0x6C3A5A14, 0xF258676D, 0x51225AC3, 0x6DA88CC7, 0x34144393,
            0x5CF9E1AC, 0x029D5DA7, 0x7340A221, 0x55F77679, 0x33FABEEC, 0xB0DD8D3B, 0xE3A87BD9, 0xF5326ADF,	0x120D9F9E, 0xC202E0BF, 0xC00D2C1A, 0x8E0D5F66, 0x242070D2, 0x6BBC83A1, 0x69C4333C, 0x78AB2262,
			0x7BD2F29A, 0xBFB0FDA6, 0xD7A3C89B, 0xFCEEB34C, 0x9F184EBB, 0x3F666631, 0x2E341742, 0x4E061271,	0x38EA16B8, 0xA968156D, 0xCC05A0C4, 0x10DA8161, 0x4147E90C, 0x76136B78, 0x39DB09A5, 0x607F1F5A,
            0x02305C3C, 0x584479D9, 0x5906BD33, 0x7B4E1463, 0x3B4ADAB8, 0x48C881BB, 0x6DBD59B0, 0x61D2F2F4,	0x423BD4DB, 0xD60C3A63, 0xCECA232A, 0x09C9D295, 0x0B6EF2B7, 0x53AECCB0, 0x585DE63D, 0x5AD0C2BC,
			0xDB0DC490, 0x89A39941, 0xE740E3E3, 0xC0A7F925, 0x42C2CB7E, 0xE3FFB75E, 0xC74BE30E, 0x6DD7F68F,	0xD8DE61DC, 0x23682BE9, 0x966DEFA4, 0x173D8087, 0x8A74FD86, 0x503CED76, 0x20E7AACC, 0xE7177F6C,
            0x7302EDA4, 0x4CA459A9, 0xEF351341, 0x79B13584, 0xB3D2BF2D, 0x31969F3E, 0xD8647A43, 0xCC3C1091,	0x702914CD, 0x24A143E6, 0xBC38E984, 0x53FEEDD1, 0xA2FA904E, 0x628AD034, 0xCD43C9C9, 0x1BA03373,
			0xE6952EE5, 0xDC7722EF, 0x5DA5ED5C, 0xDC391474, 0x8B061740, 0xA57664D7, 0x447C9046, 0xC74CDE63,	0xA284C855, 0x0CBFD2A4, 0x8B7FA9D6, 0xA1892691, 0xB14380F1, 0xA845CE8B, 0xE0F8CB9C, 0xAE6428FE,
            0xFDF01BCB, 0xAC9F1FDA, 0x436D7C64, 0x17244C3A, 0xDA57127F, 0x90595A43, 0x303A0C44, 0x6084CCE6,	0x505361CC, 0x9DECB123, 0x849D5956, 0xB443ABD6, 0xBF942FB4, 0x8665A0E2, 0x7781F1A8, 0x74F97045,
			0x563F6EBA, 0x20023C75, 0x4D142EEA, 0xB2C88D43, 0xCCBB8845, 0x859ED794, 0x3DF88627, 0x0E32FC19,	0x4FAE749B, 0xFF20DDA4, 0x425B53A7, 0x75766BBB, 0x3A5A1FDA, 0x3D9AFB17, 0x9135A611, 0x18E65A74,
            0x218CCC00, 0x9F475943, 0x8E706035, 0xEC7060E6, 0x91841A9A, 0x30FB96B5, 0x7ED7B8B1, 0x1D26FA2F,	0xBCCF2D6F, 0x4BBF5FB0, 0x5F263B8F, 0xFE7DD552, 0x7E9FE1CF, 0xF3E425A3, 0xC5C69CF1, 0xF0737054,
			0x4D434E3F, 0xB7E1FB61, 0x865AB815, 0x050309F1, 0xD91B44EB, 0x49EFC06E, 0x23F573F9, 0xDE98C966,	0x3A3CD861, 0x498F1333, 0x8CB5EDDA, 0x99A18C3D, 0x1543D6B8, 0x481626EC, 0xB2907FC0, 0xFEE3D6F9,
            0xAB0E5459, 0xFC87CB20, 0x9531BC8A, 0x4472F5F7, 0x1D6C257E, 0xC7CA4719, 0xF0BF2499, 0x39632200,	0x2F870DB1, 0xC9CFCEEF, 0x1564CA25, 0xFC90B6B1, 0x1D11084A, 0xED2EC3B0, 0x05B04261, 0xE7AAE991,
			0x7C24FA73, 0x59A93FEF, 0x2DAB08AC, 0x5E4E353B, 0x23D00518, 0x11E80E03, 0x810B4B53, 0x3E8463E7,	0xB9681846, 0xAA8DCF9A, 0xD84695B9, 0xBD775BCE, 0x835D7660, 0x98815DE8, 0xAB8B9A99, 0xD29E8876,
            0x470759A1, 0x7945F05F, 0x6FFCF85F, 0xFCB6554D, 0x388FF140, 0xF243AC62, 0xF7BAEA7E, 0x21F5423C,	0x4E301595, 0x80861370, 0x580EB6E2, 0xF6183331, 0x247093CB, 0x7E5D2C87, 0xA91DD638, 0x65503920,
			0xE18CF83E, 0x39CD4E20, 0x057D10BF, 0x27F0B51C, 0x5BADFB59, 0xDDF5D229, 0xE2A8F868, 0x72977651,	0x0289B464, 0xB2CC3357, 0xF3258FB7, 0x899F020A, 0x2D53DF78, 0x778BF928, 0x411FD2B6, 0x2C35C279,
            0x0CAE6417, 0x64D9D0F0, 0x534383DE, 0x5B8BA4FD, 0x49FA52AF, 0xB938CFD0, 0x86028256, 0xF5F39830,	0x7D9EA2AC, 0x7BF6EC19, 0xF9A0447E, 0x90221B63, 0x190887CF, 0x823A5E8A, 0x5134AA3E, 0xDE10EF8D,
			0x50863A61, 0xB537FB11, 0xDDD80995, 0x30D46F5B, 0x19CF9AC0, 0x456203A4, 0x2651F140, 0x4F990CA7,	0x545763A6, 0x08A6FAAB, 0x8797776A, 0x1AD347D3, 0x609A783D, 0xE16A106D, 0x67B14198, 0x757E2BF9,
            0x5B6E4A22, 0x0C9D3F0F, 0x0E175666, 0x51C182A1, 0xB77905D9, 0x9CAE2528, 0x670F45FB, 0x271E2FB1,	0x6B2533D8, 0x2BB7AA0E, 0x1DACB54E, 0xC640B87D, 0xF8A561A5, 0x78EF3255, 0x490CF73A, 0xD4E8E194,
			0xC517654D, 0x9CA065F7, 0x85D644D5, 0x7CBBD53B, 0x64C16D50, 0x5180B61C, 0x52948F77, 0xE6A49505,	0xD2B8D4A2, 0xA48C04C8, 0x5CFCB35D, 0x96A47386, 0x9E6E01ED, 0x56F5F1B0, 0x43555EE5, 0xD6AF4636,
            0xFD84D690, 0xEB86EA2E, 0x8AD0A38C, 0x6BF3A54C, 0x94F54A35, 0x42998F5F, 0xF329FD42, 0x788D54A5,	0x345CA666, 0x67DD261E, 0x1C21C0BF, 0x18007DA7, 0x395B5FEC, 0x071E1F8A, 0x9AFBB9DD, 0x2FD9140B,
			0x3938B4D8, 0x5B384CDF, 0x12CE8933, 0xA891717B, 0x95CB3518, 0xC8853338, 0x3D0FD46C, 0x439911B5,	0x1508DA7C, 0x2362FEBB, 0x9C888A42, 0x8B21EED4, 0x81063B76, 0x8A2C4800, 0xC5AA8625, 0xC5D3904E,
            0x1F4D7226, 0xCF0975EF, 0xD33E3614, 0xA4EEB0EC, 0xB58DC1E2, 0x1E7330E7, 0x2D6BFE82, 0xED7B9006,	0xBBA6269A, 0x10A40BC2, 0x0D974975, 0xA96B7D73, 0x189F1F50, 0x1EB1D2F9, 0xC5947ECD, 0x658E47DA,
			0x6296452C, 0xAFA1A976, 0x9F2FED86, 0xDF42E4BD, 0x84D6E4F6, 0x20A8DE79, 0xD9A89548, 0xC83ABB6C,	0xF71B86D3, 0xF421DE19, 0x5FD56A2B, 0x8961041B, 0xF80A2C32, 0x27699AF0, 0xFDE75990, 0xA207542B,
            0x5E70443D, 0xA8F4189E, 0x42A8BC79, 0x44CC9352, 0x1FAB040E, 0x79534F38, 0xA9EA2759, 0x76A26266,	0xA53BD5A7, 0xAD3766D7, 0x11E25C44, 0xF31FD397, 0x5B421E4A, 0xA78EEB4B, 0x2793F486, 0xC6E68B6B,
			0x8C5BC329, 0x709F497A, 0xE1F0740B, 0x69BBA8D3, 0xFB2B89B8, 0x35BCDF34, 0x3355FB51, 0x3D05E37F,	0x71E71052, 0x31670621, 0x18DA8740, 0xAEB1073A, 0x8268E3F3, 0x9E47AE6E, 0x60989FFD, 0xCE7A4300,
            0xC1BCEADA, 0xA11DEDDB, 0x1D412063, 0x7FECB832, 0x6168DD3D, 0x02A01AB9, 0x00B9A0F6, 0x447C0A0C,	0x29455640, 0xBFE99D19, 0xE0D208BC, 0x4751D831, 0x0A53D2A4, 0x1549C466, 0x169752E0, 0x3665C451,
			0x26C85D34, 0x4D3DAE64, 0x6777F257, 0xF964AEED, 0xF29E1C11, 0xBF35E705, 0x41FA6BBF, 0x78879912,	0x0CA3D3F6, 0xA6C56671, 0x4456836E, 0xB7338F99, 0x3D0D6F3B, 0xEB8D72F3, 0x83D6DF3D, 0xEAA2442F,
            0x2246A9CB, 0x8B74AA78, 0xC469DC8D, 0xB45F9F7C, 0x1237772B, 0x1DD964EB, 0x67963E2E, 0x5815C3DA,	0x92BDAE08, 0x6E96957B, 0x73EB002A, 0xBFF4D6BA, 0x1F762C07, 0x662601BD, 0x899CD7DE, 0x2FB52608,
			0x510D5D43, 0x6787F6D6, 0x5CA45DC5, 0x0C2B0ED5, 0xD12121AB, 0xD16532ED, 0x488CA729, 0x4CE0AE6C,	0x3968BD56, 0xA14E92A4, 0xFA329EC6, 0xADD6CE14, 0x32800EA2, 0x6620446E, 0x801A2CE7, 0x611B1FF8,
            0x5A63C866, 0x74ED0905, 0x66773BC9, 0x91319678, 0xFF71EC59, 0x1901E4C0, 0x24172D61, 0x70570069,	0x4DF3811B, 0x49539ADA, 0x3E97EBCF, 0x0B97F6B2, 0x79D3A64F, 0x4732FCF8, 0xF9181234, 0xE28E6470,
			0xF9105A1F, 0x7E980FAE, 0xD7045D3D, 0x7265B8D0, 0xF18E9FDC, 0x1D90811A, 0xE902E068, 0x4066B63D,	0x9B58BA87, 0x80B431DA, 0x13CAA8E2, 0xB64719CE, 0x527A1BDE, 0x7E972DCD, 0x0924F8BD, 0x6C969CBE,
            0x3996446B, 0xC5DCC2A2, 0x0FA11042, 0x161B926C, 0x0EFEC37D, 0xF4772F4C, 0x4A3BAC34, 0x32C97760,	0x547B0789, 0x36A3B46D, 0x6920EBD2, 0x8333222A, 0x81F14D42, 0x19A7F334, 0x4820A2C1, 0x5E8441C6,
			0xF00B37ED, 0x8B839442, 0xF3A2E006, 0x4479996B, 0x6416FC37, 0x46DB5E37, 0xEB52845D, 0x31AA3E09,	0xC95938FC, 0x55E1B0F2, 0x35C9F14B, 0x66ABA2E1, 0x3239D712, 0x0731457A, 0x940786B3, 0xC2FFBF5F,
            0xE49C7636, 0xCF3A301D, 0x635C0334, 0xE26DE391, 0x4F05D4F6, 0xCAC9C65E, 0x51A74A73, 0x623DA1E3,	0x8450F8F1, 0x94B54F86, 0x8F166F0B, 0x4666A529, 0xA328C268, 0xDB9F0A02, 0xAFC37EEC, 0xCB4CD39C,
			0xE21AEDBC, 0x3411DE42, 0x156073F5, 0xA7FFF44E, 0xC1A423B8, 0x018C00A8, 0x91B65F0A, 0x7CC28A80,	0x8E9F8B90, 0x32772911, 0xA31B9BEB, 0x6F760746, 0xD2AB717C, 0x0C46352D, 0x17D9A840, 0x7B3C623F,
			0x2D98E272, 0x3C79D3C8, 0x7327BBDE, 0xDFD49455, 0x4174F8E4, 0xE0959D8F, 0x19582BC4, 0x75413D15,	0x2F1C7F39, 0x631E541B, 0x578488DA, 0xFDF2D388, 0xE304CF43, 0xB5AE79C0, 0x6324F0F9, 0x43BDDCD7,
			0x2455BAE8, 0x687B143D, 0xF764B996, 0x97684A85, 0x775AC756, 0xEA7CD2AF, 0x280BDA08, 0x0AC91473,	0x176C3CE8, 0x2C5F3AC7, 0xFA302831, 0x6D93B435, 0x6A728C95, 0xE9A54C27, 0x3995CC6A, 0x144C2750,
            0xE9D25FB3, 0x8CFC3366, 0x68345DE8, 0xF46AE3C8, 0x9F7A6B42, 0xDC1671FF, 0x78413885, 0x1927A751,	0x382E538E, 0x3125C983, 0x4B190AE8, 0x335298AC, 0xC93F3FBC, 0xEAB40DAA, 0x903F34E7, 0x20DEA643,
			0x6565A004, 0x33C90740, 0x5A0605A0, 0xE97DFA8F, 0xFC8ED993, 0xB90FD104, 0x8304F9DB, 0x27F097DA,	0xBCD630A6, 0x79ECF85D, 0x5D48BF55, 0x3411E544, 0x78673748, 0x38F2B5FE, 0x4D8675C8, 0xD16D569B,
            0xAADA0044, 0x0CAA6346, 0x4920FD65, 0x6A8AF3C4, 0x4970802D, 0x946707CE, 0x48F90AA6, 0x253E107A,	0x545A0953, 0xC5B5F614, 0x8C95AB70, 0x426D1954, 0x8296DA20, 0x23499C91, 0xDF94BAEC, 0x64CE23EE,
			0x560E1913, 0x1F503D0D, 0x7664C33D, 0xE09918C0, 0x80BB7BEB, 0x61C9EEB9, 0x41CB824B, 0xF3D5F9A4,	0xFFD11AF7, 0x8ECEC91D, 0xA8017D87, 0x468C0942, 0xB5B4CA53, 0x49BF04CA, 0x628B3B48, 0xB7E0E2D2,
            0xDC7DDFD4, 0xD9E2E185, 0x3D7F8A01, 0x52646CBC, 0xEF2B67B8, 0xFE4A5BBB, 0x61DE67CD, 0xADBD440D,	0xD59094B9, 0xBCC1EC2A, 0x7D9A7C85, 0x1018FC7B, 0x07D99E3A, 0x5F28122A, 0x43787D21, 0x34E933CC,
			0xE168E078, 0x3B5B8957, 0x55DC62DA, 0x82F14742, 0x60ED082A, 0x78308777, 0x93E94961, 0x29F56306,	0x98DD637B, 0x0AEF3097, 0x91926284, 0x9846A7AB, 0x2AF6D035, 0xD76B727E, 0xCA9DAC69, 0x8E13509F,
            0xB08CDE2F, 0xE12ADAE3, 0x3ACA75E2, 0x4515B7E5, 0x24DA6B89, 0xFC8BBF88, 0xA6E82C5D, 0x8E5CBE2C,	0xD26C49BE, 0xE71CA3A1, 0xCD829A07, 0x252D752E, 0x046D61A2, 0x48E6D363, 0xC23A811A, 0xDBAC27C0,
			0xB29D467A, 0x0C25A458, 0x68EF985B, 0x03FE1996, 0xDA608ECB, 0x5200B923, 0x45E5717A, 0x801A9B4C,	0x084057DD, 0xF9720E32, 0x34AE010D, 0xD15E9EDE, 0x750D7C91, 0x0BF9C621, 0xF916045C, 0x374ED20A,
            0x3ADCFBA3, 0xA5BDFA7F, 0xD6826CAC, 0x0329C784, 0x01052E5B, 0x8F86C674, 0x5981B7CB, 0x3077794F,	0x6987FD72, 0x63C79F4D, 0xE27DD835, 0x72CB3064, 0x939E324D, 0x39B95655, 0xEA576DC3, 0x283A36D9,
			0xD3A01AE3, 0x59073E87, 0x4797CD3A, 0x4461D2CD, 0x451FE0B4, 0x07F68948, 0xCA999A8B, 0x63DB23B2,	0xB35D4A6D, 0xC7CD060F, 0x36118B1F, 0x145D976D, 0x836A3367, 0xCD6E2F94, 0x0F69AF42, 0x0A2E50B3,
            0x714B5874, 0x22CA2AE6, 0x5E9228FC, 0xDFE5025B, 0x6507E50E, 0xC8F04704, 0xF1A0950A, 0xE719F064,	0xFF55A7EB, 0x7E7DD369, 0xE3EB4966, 0x2F15D8DE, 0x3D76402E, 0x9CB08875, 0xC7A99CC4, 0xEAAA7BD4,
			0x064FEF7F, 0x219C431C, 0xFC96C439, 0xA091FE2D, 0x4046B19C, 0x2BA15A29, 0x9BE3CBBD, 0x16D7CF17,	0x4E72D669, 0x2795A377, 0x51A17A4B, 0x363B81C7, 0xE3261813, 0xBD6378B8, 0xFD82F1E9, 0xC60F2D83,
            0x9F7F68C8, 0x0AAFDC14, 0xD2EE12A3, 0x7163A8C7, 0x87268BBA, 0xCB0E9E5C, 0x6665C589, 0x54CDD3D5,	0xD7B85210, 0x54EF53D0, 0xE8DD278E, 0xD006204C, 0x3FCECF35, 0x7D4C16B1, 0x017B5977, 0xC01B1B22,
			0x1595E343, 0x96A4BEA1, 0xFF0A044D, 0x91DFCA6A, 0x9228B99E, 0xF07CBC7D, 0x54D6B27C, 0x9746A98C,	0xA6C7B20B, 0x64B279F9, 0xB5E69450, 0x5D9CA33A, 0xAB213CE2, 0xC2C5F842, 0xAACA7D70, 0xEA41438E,
            0x48E2A19A, 0xDB082ED8, 0x5D9329C4, 0x42332DD4, 0x4A7E0CD5, 0x63A612A1, 0xF4F67753, 0xBD0277BF,	0x66DFBFC7, 0xCEAFFCD4, 0xCE7A022F, 0xDE602774, 0xE5043630, 0x5F64AF64, 0xD7D44334, 0xD97A7351,
			0x129A1C6B, 0x2769B493, 0xF6C006F1, 0x859CF28B, 0x80B818E9, 0x3973707D, 0x9AC26E34, 0xD3F5DF46,	0x59A5BD3E, 0x97C281BB, 0xAA5F7A91, 0xE69B82A0, 0x2207AFCE, 0x5E7ED6EE, 0xA3E29041, 0x242C4989,
            0x0FA3EA1E, 0x6456EE8D, 0xDB6FE1C7, 0x012053D6, 0x1FE9936E, 0xE6EAA90A, 0x491EA39C, 0xC44794B5,	0xE7D1D377, 0x55FBE239, 0x2E8E5400, 0x1ED36057, 0x6FDE6B11, 0xDD3DD8CF, 0xD15DC268, 0xDA8B03A1,
			0xCDC18FA6, 0x022473A7, 0x7262D306, 0x76C519D1, 0x619D9674, 0xC5A68A95, 0xB81C691F, 0x1A52BCAE,	0x43BB0FD5, 0x2F099F9A, 0x47311A67, 0x6FF50AF4, 0x69A075A3, 0xB1D0C306, 0x7911E4CE, 0x94339346,
            0x89C4970A, 0x27E4658B, 0x2E4E12CF, 0x9B792B19, 0x8D25F30B, 0x82798311, 0x3D12A5D8, 0x7CAB4630,	0x4EA71CE9, 0xC013CE74, 0x010F7F58, 0x85055417, 0xB6EEE921, 0x76F670A7, 0x31C82CEF, 0xB4D826E4,
			0xAB48FBDC, 0x1AADBE0C, 0xBEDD7978, 0x4334D82A, 0xD3443C5D, 0x1289E8AC, 0xAC32476F, 0x31B48151,	0x863085A6, 0xD52D6E9D, 0xBC9FA507, 0xF4BD7BC9, 0xF6E5D0C7, 0xFD080C71, 0x4DAD66FA, 0x87C3FA33,
            0xED98EF55, 0x9705F72E, 0x2885DCD6, 0xF47F08EF, 0xF4877417, 0x355E12F3, 0x74665192, 0xEC2E75FE,	0x2266CDC4, 0x7E36A996, 0x64405FAD, 0xA38B11F7, 0xA6DFDEBB, 0x28E1679A, 0x6380EE0B, 0x03D6C2F4,
			0x04036000, 0x7EC0178E, 0xA977D937, 0x5D2C6754, 0x3861C23A, 0xF95F57B1, 0x01A4CBA1, 0xC726AECB,	0x6D67B820, 0xF52E7BCC, 0x81134A6A, 0x75C59FD2, 0xC0A8D3BE, 0x4DBA2254, 0x7D76710B, 0x2412C473,
            0xC0A1751A, 0x92A4F27D, 0x5EAA1D84, 0xF83F41AC, 0xED63E483, 0xD94518B6, 0x15221A96, 0xFAD1EBCC,	0x4185DD05, 0x6F6B0BCD, 0xDC29BDF2, 0xF8E5DDC7, 0x0C3B45D4, 0xBCCCACC7, 0xA30AA0F7, 0x80F8332D,
			0xEF7729A9, 0xCBD8737F, 0x7438458C, 0xF719F229, 0x015CA66F, 0x4D1031ED, 0x4E6EACD1, 0xC424958F,	0xD011B1C6, 0x5B7CB492, 0x8BDF5810, 0x68EAADB4, 0x52C20EDD, 0xD35535ED, 0xB50FF153, 0xB0DE332C,
            0xB0019CC5, 0x1806D92A, 0xEBC88878, 0xE3ED5769, 0xCA07FD85, 0x18D251A4, 0x6E6B1684, 0x9BCCB659,	0xD511E07C, 0xFAFD4407, 0x37F618A6, 0x641947B4, 0xC0529685, 0x9711836F, 0xD1FBEC06, 0x3D358E12,
			0x3FEDA387, 0x2168C3CD, 0xB7970C23, 0x2C5C3FE6, 0x64AEDDEF, 0x81FB17A7, 0x5587DD9B, 0xA8883A18,	0xFB3ABE69, 0x9C864A22, 0xC8B8DBBC, 0x3C9FD110, 0x9DD933E3, 0x4FE71866, 0x2334F2D4, 0xBB993513,
            0x272AD2B9, 0xBB50AB84, 0x2D45AD97, 0x64F7F9F6, 0x45A62284, 0x9869FDE3, 0x34B64E10, 0x825AD22B,	0xB42CD543, 0x6403E8E0, 0xE41E76C4, 0x3B8D18E7, 0xC87180E1, 0x71D3B652, 0xA001636A, 0xE11DD6E8,
			0x7F3B3EAF, 0xC5BCB6E3, 0xB02D2050, 0x9B3EE4D9, 0x2709D66E, 0x3170C601, 0x5A02269D, 0x14B757F9,	0xC4C2D267, 0x5E3D3DE4, 0xE4C50735, 0xA4490B09, 0x97D4B8C0, 0xD3A242D4, 0x557E4894, 0xE85A2C54,
            0xD70E935A, 0x2EBBA823, 0x254E9660, 0x0AB661C6, 0x6E7170B4, 0xB1051978, 0x3226DD90, 0x4508A2DB,	0x317A5A4B, 0x84BF59B6, 0x389C73C0, 0x12AE2C8C, 0x408415BE, 0x9D9672C2, 0xDD34A2C4, 0xDB0ADD48,
			0xB571A2A1, 0xE791F660, 0x301331F8, 0xD37B3F57, 0xBCB4060E, 0x9B4F0009, 0x86DB9144, 0xCB8F7249,	0x89447CC7, 0xC839F013, 0x1D1F5D20, 0xB6FA00B2, 0xD4309AE7, 0x738372A8, 0xC2C69A0A, 0xE7A25603,
            0xF29A843A, 0x88110906, 0xA1C02708, 0x47F7BD53, 0xEFE8DA86, 0xB9E7D527, 0xD5E65EFB, 0xE2244E73,	0x41317928, 0x3BC8C372, 0xEFC3F265, 0xFB7194DF, 0xD00E143D, 0xE1347E12, 0x5CE3A8D0, 0x09139CF9,
			0x86910786, 0x9C9AD421, 0xCDADE8E5, 0xAF3B2C74, 0x072405EA, 0x23D21B3A, 0x057E0120, 0x9CC9CD98,	0xA4A52B12, 0x6BC570BA, 0x9A783975, 0xE95187EC, 0x2694AB1D, 0x050E4C59, 0x0BE81C03, 0x7588F27B,
            0x9CF1CD4C, 0xBB9BD81A, 0xB40BF37A, 0x8812BCB0, 0x3DD214D0, 0x9FB28697, 0x7681A30A, 0x351D62D5,	0xD3BD8474, 0x0A30D45D, 0x18935109, 0x3AC31769, 0xF7C49B52, 0x9A19E520, 0xDF4C750A, 0xB57BB5EA,
			0xF116756E, 0xFB528147, 0x44FBF1BB, 0x6AA37B96, 0x3247E7CB, 0x493A3D66, 0x55E38EC6, 0x1E160621,	0xC2D1680F, 0x3E20C669, 0xE032BA24, 0xAD801705, 0xC32ACF8F, 0x089F705C, 0xE820A6FA, 0x939610A4,
            0x8CE8F20C, 0xBDD92CDC, 0xAC5FCA0D, 0xCD6E896D, 0xC4E67016, 0xDE1CDABB, 0x772DAB2E, 0x1F1B02F7,	0xCA209007, 0x1555AF14, 0x8142C157, 0x813410F7, 0x6FF27167, 0x09FE74CA, 0xE488392B, 0x3CDFA9DF,
			0x0455AE63, 0x2D6EBB68, 0x895002DE, 0x736D14D2, 0x921845CA, 0x8D19DE4E, 0x42805500, 0x2597E657,	0x472BF942, 0x7662512A, 0xC7E101D6, 0x59BACFBF, 0x1C1BD47C, 0xA689CF2F, 0xEFFB402E, 0xFFC56A2B,
            0xFC6B2FB8, 0x6783A490, 0x9AB21E97, 0x4363C677, 0x6E5ECC51, 0x2275C903, 0x1679DD51, 0x737E3E60,	0x1DDAF4BB, 0x9E8ACF73, 0xA2DC79C9, 0x59D65280, 0xDE896697, 0x31FE6047, 0xC939CC8C, 0x2B42FBE2,
			0x7FD36698, 0x41B9BC13, 0xFFA89158, 0xD221CABB, 0x161263CA, 0xBE2531C2, 0x42255757, 0x84AFC3C8,	0x9A4D540D, 0x50B65A40, 0x8735B3DB, 0x25016B86, 0x2EC23DF7, 0x47F0C9F3, 0x00D9881B, 0x19EF692D,
            0x9C58EA2B, 0xAE84C2CB, 0x139ECCA6, 0xBE67F318, 0x27033BAE, 0x552152C0, 0xEE1D1E28, 0x4D8B9FA7,	0x649180C0, 0x9B30AD5D, 0x77EB24A4, 0x6BDDFE24, 0xCAE441DB, 0x6406B254, 0x5791D6AF, 0x3DF16A58,
			0x0FABA277, 0xF58C74C2, 0xEE0E00C5, 0xC0D983C0, 0x06C45735, 0xB789880C, 0x91452EAF, 0xEDE2E750,	0xFE5B3790, 0xC442E405, 0x04E7F8B0, 0xF3C7E7EE, 0xFF3D9080, 0x19326549, 0x9BA9D140, 0x9238D2C1,
            0x197C4281, 0x603EBC1A, 0xB2F4457C, 0x6A2975F8, 0xCF871C09, 0x09CB0B16, 0xE3427F92, 0xA9E6DC50,	0x8BB7DA79, 0xFA4E0D6B, 0x060BC682, 0xF29D967F, 0x83387073, 0xABACBDA2, 0x6FEA154E, 0x107DE4BA,
			0x0272F3A1, 0xD6ABC42B, 0xF0E8E761, 0x56615245, 0x24745EE0, 0x2ED30D64, 0xFFC16CC2, 0x59FF1406,	0xD27F56D8, 0xC4D37455, 0xD4FCE4B8, 0xD500A73B, 0x2AC545EA, 0x41840C07, 0x6CE234B4, 0x6B0406D0,
            0x8D75CDBE, 0x07C2A43F, 0x0BE50666, 0x3CD46599, 0x7399191D, 0xA248C546, 0xE94D2A4C, 0x451EE646,	0x93CBB084, 0x7AEBCF2B, 0x69513531, 0x4BF2FE26, 0x7273F4C5, 0xF3998756, 0x87F07B11, 0xBFBC842B,
			0x6121349D, 0xC698C9D5, 0x78AE6425, 0x2E3BCB8B, 0x6A539873, 0x6A7D6169, 0xE16367A4, 0xD623F7FC,	0x08138DFC, 0x77CB75D8, 0xDC438A85, 0x5F8F3562, 0x58B19AE4, 0x40AE475A, 0xB5CB826E, 0xCEF47F17,
            0x7EE64AD5, 0x8E345A50, 0x80CF9527, 0x3789F35A, 0x51B31A10, 0x3A378CFA, 0xDD7E8D22, 0x5866289B,	0x82160CB4, 0x34A4F8BE, 0xFB533E09, 0x962AF4E1, 0xFA08A2EB, 0x6901E02F, 0xCED79CB4, 0x98EEBB86,
			0xBF324550, 0xE1A78E1C, 0x038B2D13, 0x59D1B13D, 0x0AAC8A62, 0x5F1D42BD, 0xAF1E0833, 0xAE3D6A21,	0x4DBF3CDC, 0x6635738B, 0x15EF70E8, 0xE1ECFBAA, 0xC1FC7386, 0x9AB2188F, 0xFAF41C8B, 0x702AFDC1,
            0xA6EED5B1, 0xC6C1C07C, 0xA0E30FF6, 0x281C83EE, 0xC2CF77E3, 0x9956A00D, 0xCB19D944, 0x34498D48,	0xEE8C4D27, 0x8A4E45D4, 0xF79AB9F6, 0x6C98BE64, 0x3045277A, 0x7B895120, 0x92ECC9B4, 0x83F8E3FC,
			0x3AE92E91, 0xCFA5BC97, 0xB17C4438, 0x1512DE0D, 0x818DE4B5, 0x2A00834F, 0xF81D1A89, 0x3C83C57A,	0x3EC9973C, 0x3FC7ED65, 0xCCEF7407, 0x679BCA5A, 0x67E48536, 0x00404F09, 0x97EB1B27, 0x6342AD37,
            0x0870AF1F, 0x139236E5, 0xC6376DFD, 0x16F52AD7, 0x7B397D69, 0x581B5C37, 0x410431EF, 0xCF806861,	0xCE34104E, 0xDB8577CB, 0xC0488859, 0x5EA2280C, 0xC290DCF6, 0x085AC49A, 0x2670EEA8, 0x64F62D02,
			0x7DA9F9AE, 0x91237273, 0x95A91BA3, 0x29B69B28, 0x8F81C230, 0x5A6353E7, 0x7A27B1A1, 0x88B83324,	0xDE833438, 0x01788FD0, 0xCC30713C, 0x72F4BF2D, 0x46E835FE, 0xBDBDFAA7, 0x86BDAB21, 0x68D92913,
            0xE9468D22, 0x6291C457, 0xEA361458, 0x4D24F04C, 0xB155C535, 0xDB337A2B, 0x6542E7B3, 0x258AE254,	0x04A7E813, 0x2CA91D04, 0xE81CFA8A, 0xCD2BD155, 0xFB1D96A7, 0x148F3C3B, 0x8DDD3A66, 0x5D215835,
			0xE19F6F7D, 0xA5AA87CA, 0x79D78EED, 0x8B5BB306, 0x4B034C5E, 0xE58B379D, 0x79F3C4BF, 0x7379AFC2,	0xFE062BB4, 0xDB803570, 0xB5C21144, 0x71A21EC7, 0xDA3DE07E, 0x1C4CD88B, 0x1C7060BE, 0x13561E52,
            0xB31809EF, 0xA646349B, 0x73DD91E2, 0x82CF4766, 0x37E98B25, 0x9C4207A3, 0x1D44F44A, 0x1E830AC4,	0x0D8CCBB7, 0x64F8DC56, 0xA25905C9, 0x106B4C3D, 0x302F22CF, 0x3D2BE3E4, 0xD21A985B, 0x523B5E4D,
			0xA83CCBF1, 0x041F98AD, 0x45C9F7AD, 0x13FA63F1, 0x384E1EC4, 0x3726F05D, 0x07E87DF7, 0x4F67A16C,	0x15A2D079, 0x70460247, 0xFEA326BB, 0x563B5C74, 0x26493188, 0x9874CDA9, 0xDF38BCB2, 0x1A71A16D,
            0x67165B1F, 0x2FD5284B, 0xF6DE31AE, 0xC2EA2091, 0x7B7B6ACE, 0x01BAA16A, 0xC94064EC, 0xD23E26DB,	0x04F2A06A, 0x188B1ACC, 0x5D3BC00B, 0xB8C3F1FA, 0x86B5A029, 0x51BEAB28, 0x92610484, 0xBDC547B1,
			0xB14045FF, 0x0BC8352C, 0x8823CFAE, 0x80F47425, 0x34D88FD2, 0x53CDB5B7, 0xE366566D, 0x9BB14B91,	0xE1A34349, 0xB9F83060, 0x076DD5D7, 0x3B94309B, 0xE716920D, 0xE1DFC216, 0x98943693, 0xBD2357C2,
            0x51E495D4, 0xAAB47A6B, 0x95EF37DF, 0xF239F3C9, 0xCF15BBF5, 0x2CDA8826, 0x5F1945AD, 0xFE226BD4,	0x22B45626, 0xC7FCB8CE, 0x8AF74597, 0x80F8747E, 0xC9BA9A23, 0x69A70AAE, 0x9819664E, 0xF73A2EA0,
			0xB9F65998, 0x35C312CA, 0x0F3F2B5A, 0xB6427555, 0xFBAB60F7, 0x0C7050B5, 0x0BA95804, 0x42C35E2A,	0x126E8D5C, 0x4A7304CF, 0xB8B9A646, 0x447B2CC0, 0x1F0B22E7, 0x0009EC74, 0xF461C589, 0x5B63F5B7,
            0x510CA296, 0xCD64D232, 0xDF12C6DA, 0x1593DC86, 0xF106B032, 0xA98C044F, 0x09E3866B, 0xC6B817D8,	0x88BAA1E5, 0xEB426D88, 0xFEDC4A68, 0xA667BDF7, 0x21B4FCBB, 0x7FB3953C, 0xE7895E59, 0xDD1CD3AF,
			0x6AA6C014, 0x0D805BFC, 0xAC34AC85, 0x586A2366, 0x9F220CB0, 0x00D56A8F, 0xEE2017B8, 0xB10D03B4,	0x2825FE78, 0xD2341F12, 0x5D498FD0, 0x3B68C74E, 0xF76E4318, 0x819A296F, 0xF5CADB4A, 0xEA2B747A,
            0x82550AF0, 0xA11CF806, 0x9DD45634, 0x30D18336, 0xAF665A88, 0x983A7232, 0x7C59EBDB, 0xB453C1BA,	0xB6966F35, 0xB687D205, 0x2CE1310E, 0x58A895E6, 0x80501D54, 0x5D5F5F9B, 0xFC263E7F, 0xC561497F,
			0x2904BD9B, 0x54276169, 0xB8DA3D51, 0x3EF64E09, 0xF98B7A85, 0x971B9C1F, 0xCB5DD06D, 0x6440F47B,	0xFCF2B0D6, 0x6C3CCB76, 0xD76B047F, 0x53DF842B, 0xDB1BA3E6, 0x0BBFF0B7, 0x6C818E78, 0x0C6796E6,
            0x4B7F0329, 0x44FE39C2, 0xF5B1E0B4, 0xB24D71FA, 0x70D6B2F7, 0x83D5471E, 0xBA4B723D, 0x3E5142EE,	0xF409DE80, 0x11CE7B44, 0x05017622, 0xE7EB8766, 0x6BA15721, 0x7D89C8C9, 0x6209AC6D, 0xCC71A616,
			0x2AB73ACB, 0x228E577C, 0xB8F99901, 0x4AC61D50, 0x8AF0762A, 0x73B92260, 0xEBD88E99, 0x03D94221,	0x328DCE96, 0x58373F53, 0x641EC8E8, 0xE2BD9F1E, 0x9A0F8187, 0x4D3F7128, 0xC5027E0A, 0xC0FFBC64,
            0x54947028, 0x20A71032, 0xBFA45C7D, 0xFD9263C2, 0x64DDD1F6, 0x0C3C09AD, 0x3289E8A9, 0x958DAC0A,	0x66E01B76, 0x36CC1E7D, 0xED86A5FA, 0xCFD11266, 0x405592B5, 0xCDCE5B11, 0x37EE6494, 0xF7B86172,
			0xB496AD8D, 0x68633FF1, 0xD995CFA7, 0x184B5CD3, 0x38B94019, 0xB6B8343D, 0xC726D03B, 0x336DF7B3,	0xB534452E, 0xE1FD7EC1, 0xC9F044E1, 0x0499B521, 0xF3488082, 0x4CA7A623, 0x6C6FAC92, 0x68CD4B17,
            0x68A62AFF, 0x2B42F80D, 0xD80CCB48, 0xE8913CAF, 0x0AA0E1B8, 0x813B7898, 0x47AE6F26, 0x45687839,	0x0D6F2852, 0xD8160A9F, 0x20ADDBA0, 0x2862680C, 0x3B04006F, 0xFF6F519F, 0x1B47C4CB, 0x783FDA4D,
			0xEC1CBE6A, 0x0D5E05CB, 0xCD09EFD6, 0x2D22F17C, 0xB832632C, 0xB7D133E0, 0x2F0D030A, 0xC187E25A,	0xF68D529C, 0x865D1827, 0x01582D83, 0xD6EBF7A5, 0xC78CAFB5, 0x87511C85, 0x6805A819, 0xC8C5EAF4,
            0x7BC506A4, 0xF6356FC7, 0xE6E4C8C3, 0xAA146237, 0x566A69DB, 0xD416D720, 0x491949A3, 0x6303B6D8,	0x3B2F13C5, 0xD6B9E0E2, 0x3528555D, 0x5EAB46C2, 0x756001C0, 0x56C9FE30, 0x16A14F15, 0x718BF0C1,
			0x1EC3FD9A, 0x4D26A6C2, 0x0F65DBD6, 0x36B805BA, 0xDC397D07, 0x18C8AB90, 0x740D8D41, 0xEDA36C78,	0xB676F014, 0x0D8D5D92, 0x1EA3DA91, 0xF0210C26, 0x039116A9, 0x7BF52BA6, 0xF91E2B1B, 0x2E077C88,
            0x2BA783C4, 0x1725E29C, 0x2CDF6BB7, 0xEF5BF4FE, 0xA0F37D09, 0x7B394F55, 0x105A6A1F, 0x527605E7,	0x71F3CB73, 0x6B330E7D, 0x82038256, 0x3BF07474, 0x882D74D1, 0x6708EF3F, 0x6C3437AB, 0xA5AFB9BA,
			0xCD19C7DA, 0x5B8DAD98, 0xEE290D49, 0x6FCF2552, 0xBEB2D4C5, 0x7A2318B7, 0x24164824, 0x5A6EF2C9,	0x4B7FE3AB, 0xB0786DB6, 0xF3306249, 0x2E627133, 0x834C5C8D, 0xF581A933, 0x216A5E04, 0x0F3F60C9,
            0x273BDD35, 0x668443D5, 0x644AE132, 0x54571A16, 0x16B861A2, 0x3A1B0093, 0xF358EAF0, 0x7200C5FD,	0xB1437F89, 0xBDBF9FBF, 0xE70E05C5, 0xF85F822D, 0x21F28F37, 0x0350857E, 0xCBB4641E, 0x9A0BBEFD,
			0x165E8EAD, 0xF821ED58, 0xE9DF275B, 0x533C9F19, 0xE297D7DB, 0x29836071, 0xF7948458, 0x8FE87448,	0x04D10E93, 0xE2506CC5, 0x1B3CBCF2, 0x640F34F4, 0x42B2BE5A, 0x51051705, 0xD2AC5585, 0xA3A16ABF,
            0xCD18412A, 0xEB9000B7, 0x05284335, 0x0EA125D7, 0xFFA4DE47, 0x80A9DAE7, 0x95895C01, 0x265083E7,	0xFB87B45C, 0x6A382CE5, 0x7CA7DD37, 0x165FF0D9, 0xE94FE83D, 0x55A1294E, 0x66CCCC09, 0x01AD2C4A,
			0x8E8CC99E, 0x2D48870A, 0xE0E3AE70, 0xEE366CEF, 0x7B65D9DE, 0x8BBA869A, 0x5EC41227, 0x29A9E9BA,	0x58058D28, 0xC9EA9D7B, 0x5E55E64E, 0xB5627B72, 0x1F874F96, 0xDB1238D1, 0x2B196BFB, 0xAE63A1E3,
            0xDC356D6A, 0x20E92187, 0xD35B49CC, 0xB6EDF197, 0x0FD92DB9, 0xC7977167, 0x018330D8, 0x13B07589,	0x057A740E, 0x2CEEB111, 0x7E8A108D, 0x3D283430, 0x0B171035, 0xD0A1AFCC, 0x12003680, 0x3827FC02,
			0x5DFAB422, 0xBE34FC1B, 0xCD088401, 0xD9419EE4, 0xCEB4E674, 0xC736DBF0, 0xB0729A08, 0x4981E08F,	0x9FA1E346, 0xBFAE96D3, 0x016C7635, 0x29FB0E77, 0xBA82FA42, 0xC6904B5D, 0x0668A586, 0x04728D5F,
            0xDD80DDAB, 0x4F4DC8AC, 0xBD0098AF, 0xC17FC0F3, 0x2AEEF576, 0x6571E4DA, 0x34B132C9, 0xEBF12575,	0x500469C6, 0x99F5E87D, 0x6B84A9C2, 0x3FEBE7C7, 0xC743A01B, 0x161A3D13, 0x46E4C335, 0x7B4A9B0C,
			0xDDB37B86, 0xBD625C67, 0x7DD8C0D2, 0x513ECB54, 0xD889C4DB, 0xA6554E2A, 0xA0605B3A, 0x1561774A,	0xA34B2BF6, 0x1C7B8265, 0x7EEB182D, 0xFE2D80E7, 0x1A52BE3C, 0x5C6F2F86, 0x531F822D, 0xA2E07E4E,
            0x7BCC82F0, 0xD685B873, 0xED65224E, 0x73AF2006, 0x691BBE66, 0xEB154BA6, 0xA50BAC77, 0xCE885D4A,	0x04DA5DD1, 0x1F97C2C4, 0xA048BC2B, 0x8BB783F6, 0x434EA4FD, 0x645D8FD2, 0xED358934, 0xEA620FAE,
			0x2BC99601, 0x13310B7C, 0x1EAC17EF, 0x7B6BD9E9, 0x21586D5B, 0xDAB36D1F, 0x017F4826, 0x2A922F34,	0x39DC7CC3, 0xD46AB987, 0x6FD13E54, 0x4E8FCA07, 0x05A81436, 0xC8EB5D3D, 0x27756133, 0xADC3739E,
            0xB1F42D10, 0x834B17AD, 0x8A1785CC, 0xCC170464, 0xA489E838, 0x8EC91CD3, 0x1427EA6F, 0x5BB6CA52,	0x0F9DEF81, 0x5B1C6067, 0x320FFF52, 0x1D2CAD3E, 0xB884633C, 0xE1D008A4, 0x9E67FE3F, 0xB900292E,
			0x71C8650A, 0x4A75ED81, 0x6B441F95, 0x4273E584, 0x6FFF8364, 0x5CC4AD2C, 0x3F8A87FB, 0x01661635,	0xE89168C3, 0xF61EE17F, 0x53B0B92B, 0xB874D5AE, 0x79B66A6E, 0x082B3B7E, 0x03A05489, 0x47C71E1B,
            0x6351D8D6, 0x554A53B6, 0xC2FE6F44, 0x047331C7, 0x5769A4D1, 0x63543D05, 0xFFE4FB5E, 0xE3BDABBB,	0xA13A39B0, 0x0B0DFC23, 0x444F3D10, 0x83DE3EC2, 0x1BDADDEF, 0x6615AB3A, 0x2F03C81A, 0xF7CF0062,
			0x18F498FA, 0x5A06A79D, 0xDE62CBBE, 0x8B980A03, 0x5D670119, 0x52FE189C, 0x3A9DC9F4, 0xC63718E8,	0x209C17E9, 0xC0290766, 0xCDF72B36, 0x5E0777EB, 0xF81CB916, 0xCA8C0CA1, 0x755F8DD8, 0xCFC6D3CC,
            0xCCD00815, 0xFC06FCCB, 0xE89DAED3, 0x15562D36, 0xBB84D86B, 0x1153EEB3, 0x41E9E142, 0xDC136ECF,	0xEE4F9A6A, 0xCC092D0F, 0xAB09CBFD, 0x16FB653D, 0xC5EA4BA8, 0x93485443, 0x9FC3B93E, 0x12BFE729,
			0xEE863D06, 0x862EEDC9, 0xF538AFEB, 0x8855A4AF, 0x73D58A40, 0x80866E82, 0x890C65B1, 0x8B268567,	0x9FE11CA3, 0x207CD13D, 0x70794445, 0x680A631C, 0xD2D75047, 0x26BC47F2, 0xA6BD4A77, 0xF04FF1B0,
            0x11450B5F, 0xB00C0C12, 0x3E05B343, 0x08964590, 0x7E12E2E1, 0xA41B8E1E, 0xAE2C08B6, 0x9EA30A4D,	0xFD7728DE, 0x7B12E062, 0xE9D3DAE3, 0x3392D5AC, 0x5A2BCE77, 0x73F43D40, 0xC229092D, 0x7A70230E,
			0x3D4E09C4, 0xA82EB989, 0x97672BFD, 0xC8D2A251, 0xCACBE25E, 0xD3758844, 0x4D013342, 0x30F87DDA,	0x34796DE1, 0x9E16D310, 0x4EA7113A, 0x550A7E97, 0xE8EEC298, 0x97C00AAB, 0x37E28B2D, 0x6421C7B9,
            0x3E2BEA37, 0x9291A2BF, 0xABE946F5, 0xC7453F11, 0x85D4D2B3, 0xD1C72AB2, 0x3E8A73E4, 0x6A223C47,	0xA3396505, 0x2B6BA226, 0xC9DC97D0, 0x08C740FD, 0x9539A42F, 0x9133A7C2, 0x3BEE3300, 0xAE067EB6,
			0x1B49CE3D, 0x2ECCD77B, 0x22F2EECF, 0xCA8F3CC5, 0xC30026F7, 0x396F13B7, 0x7B0D2FCA, 0xFA17CE20,	0x254849D1, 0xBC5E5ED9, 0x1EC0A8DB, 0xDB93B9FB, 0xAC56A806, 0x51044595, 0x72EB10C7, 0x7A93ABDD,
            0xE94BA7C1, 0x89913342, 0x94B264C5, 0x6DF3F80F, 0xCFB195F6, 0xFF4819B3, 0xF8E0EFB4, 0x9F01F58D,	0x1469FD09, 0x4A5CE916, 0x3F341473, 0x543225CD, 0x83E519B9, 0x44D24C65, 0xC51BBD0A, 0xF4B2E5B5,
			0x7A3EEDF5, 0xE176F013, 0x773D1D3B, 0x09E20B72, 0x0B2C19B5, 0xCA537B9F, 0x5C2A1BCD, 0x87742395,	0x98C347B4, 0x2A5C43E9, 0x30FF8772, 0xE7C2D518, 0x9E338D06, 0xA8E0E905, 0x048E7E9B, 0x9C6391B2,
            0x9B6C90B1, 0x0397782F, 0x42241FD4, 0xD0A00892, 0xE54A537C, 0x114E9E0D, 0xEC104ADF, 0x35363785,	0xC03C10A2, 0xBDD484A7, 0xA8DF87ED, 0x2D786902, 0xA862CB65, 0x06431C29, 0x2C017539, 0x022FCF0A,
			0xF545E541, 0xC2E11321, 0x14ADC3EC, 0x6ACA7CA9, 0x381DACDE, 0x2E249493, 0x7FF95B93, 0x368CA4C8,	0x318EED58, 0xF275A383, 0x2FDA74DB, 0xB7A9E124, 0x08A25FED, 0x4B76666F, 0xE1E4E406, 0xB2956B8D,
            0x65AA6867, 0x94F90A78, 0x3ADBD500, 0x1EBE5265, 0x370DF592, 0xB4015DF2, 0x1221ECE2, 0xC42B9241,	0x7735A518, 0x87DBE227, 0xF8D77419, 0xE721936A, 0x55079551, 0xC4B16BB0, 0xBDE829BD, 0xEB0C0D02,
			0x20B9D4CD, 0xF0954F8D, 0xDCAE1374, 0x3CC8D776, 0x6FA821D0, 0x005AE676, 0x1E02AC4C, 0xE9B3966C,	0x648D3A45, 0xBCB436CE, 0x71BDB4FC, 0x4E4B24A4, 0xB81A8703, 0x03CBB7FB, 0xD0476D7C, 0xCF62E8B0,
            0xF29BD0F5, 0x63FFB698, 0xC991E935, 0xCA0174F1, 0x4724D467, 0x799CD274, 0x148266C2, 0x933AA554,	0x175FE66D, 0x67F1F4D6, 0xA9FBD3AB, 0xF8B2F042, 0x698B67E0, 0x6F8482C1, 0x6ABE406F, 0xD0C3BF74,
			0x1DB71B06, 0x58C71CD2, 0x5B65DDC1, 0x8A452222, 0x5F8FF0F0, 0x7664C748, 0x2F4A56B1, 0xEA77649D,	0x434E6319, 0xECC630EF, 0xB798EADD, 0xBEAB3F34, 0xAEB2405E, 0x9D49A80D, 0x26D16D13, 0x9E0B5481,
            0xBBE5CDE3, 0x0FDA42C9, 0xBDDC486E, 0x501BEB77, 0xCD6C526A, 0xEDFB9424, 0x250B81BF, 0x693E4192,	0x06AB93DE, 0xA1C04FE5, 0x8F5D5D2B, 0x8056B1ED, 0xED0F9AD8, 0x9B3774ED, 0xCF093AB3, 0xC4234DA7,
			0x71EF25F5, 0x83A41F18, 0x234327C8, 0x4F9EB15D, 0x5B308DF9, 0x41814187, 0xA6DA2A1B, 0x5DB3F694,	0x4835DBA7, 0x1C485D38, 0xEC10BFA0, 0x12ED221F, 0x59182EE7, 0xEA991BAF, 0x30728BA4, 0x0A566A7E,
            0x5CD70212, 0x6DDF4309, 0x7C1EC435, 0x5A361BEF, 0xC88F09D8, 0x2E3A5B77, 0xA06AF297, 0xACA56B4C,	0xDEE8D658, 0xD9966003, 0xE78FEA83, 0x0167AB52, 0x710FF5F1, 0xD30B492A, 0x9333521F, 0xD2937B97,
			0x54AE24F9, 0xC1570DF3, 0xFF05557A, 0x3CD3AEFA, 0xE53EE865, 0xE41C00AC, 0xE7A81FBC, 0x83A271B7,	0x5A3D2FE5, 0xDE5769F5, 0x5A8DF86A, 0xACC1BE2E, 0x4BB9A92A, 0xF08A2A67, 0x573CAA3D, 0xF4642B3D,
            0xC67F9933, 0x5B9CEE42, 0xB8DFB35F, 0x9DF7C624, 0x0B7ACF2C, 0xB6B7613A, 0xFD85DB32, 0x6A96F35B,	0x20D21111, 0x205BA57A, 0x4C85022B, 0x7C7DAA89, 0x6C815F9E, 0x6D685D92, 0x45C08858, 0x17EB504A,
			0x0B9D241A, 0xF7DCEB37, 0x6A9F4F12, 0x48CFA018, 0x25B7C190, 0xF4F78A70, 0xE21DB67D, 0x7D78186F,	0xE0BEA9E5, 0x6BB51E26, 0xA6758C10, 0xC35FF2FF, 0x2FA421B6, 0xA015AE0C, 0x0D63A81E, 0x0ECE2F76,
            0x15C85601, 0x22436481, 0xFBA8F8B3, 0x4E5C52E1, 0xDF04E362, 0xA8B1677A, 0x470D0AB3, 0x17D67B00,	0xA82BDAE3, 0xF156F1C5, 0x0318A12C, 0xE124FF2B, 0x4BFDEBA7, 0x4E07F2F0, 0x62789E4E, 0xDB01C418,
			0x1FF04F3F, 0xA0E201CE, 0xF526F5FC, 0x0608F72C, 0xA39242E7, 0x1AC54A78, 0xBFB8C1CF, 0xF482BAF9,	0x17A12DF9, 0xB021F4EA, 0x1417D217, 0xC5ECCE3D, 0xAE10C2FE, 0x97DF3098, 0x56349889, 0x916F315B,
            0x09C9B844, 0x24CD8E05, 0x2369E491, 0x0EC6A679, 0x4AEE0EB4, 0x2B09618F, 0x30137233, 0xAA25F6E5,	0x0EF5169B, 0x9A7EA32A, 0x77407F5A, 0xAD4B80E1, 0x2CA8EE8E, 0x8539CAC3, 0x0946B342, 0xA8963D7A,
			0xE3274461, 0x0FD170A4, 0x17337887, 0xD67BFAE3, 0xB92D8FDD, 0x610F4B8B, 0x1AC0A858, 0x3EE2D982,	0x1B925EF2, 0xE7A48DD5, 0x559EAC03, 0x0544B971, 0x36602C19, 0xBE8C9BA7, 0xD7B21F36, 0xA5F6507B,
            0x368481A4, 0x5658C479, 0xC7882C0B, 0x58EA98CD, 0xF0AC1E6F, 0xBAC42AC2, 0xB480591A, 0xEB336624,	0x4EA07230, 0x6151FD5B, 0x31F8A5F6, 0x3A226A4A, 0x3E74319C, 0x0270138A, 0x52EEE6D8, 0x79A9BD2D,
			0x4DB44788, 0xD8BB8EE1, 0xBB2CD547, 0x0D45D2F8, 0x7D342D40, 0x9FD72CC7, 0x7B35E6BF, 0x4951F015,	0x7F315835, 0x78BEB54F, 0x92D9B1F1, 0x488704FC, 0x044CEDD3, 0xBC4ED01C, 0xC3F4F7BD, 0xECF6A6BF,
            0xD8CFB7EE, 0x04B85E08, 0x90DA5FAB, 0x42CACB93, 0x8667C213, 0x50FE6D8C, 0x5256D041, 0x404F1674,	0x7097124B, 0xA187E62C, 0x56CF0790, 0x56750AD3, 0x196BFEE8, 0xF9B71EF3, 0xFA406DE6, 0xD800D619,
			0x3CF60FE0, 0x35458B83, 0x8361FBC7, 0x25D1A3D9, 0xCF678904, 0xA491690D, 0x87A40E4B, 0xD7AEFCDA,	0xEF80376F, 0xD5C81B96, 0x8084D896, 0x205B94A3, 0x56B7DED7, 0x25072D5D, 0x2AE7510F, 0x68D5C868,
            0x6B91B5AD, 0x0D768CC5, 0xB3EE8A20, 0x6D7809A5, 0x2A3420AF, 0x358C7C56, 0xBC1FA52F, 0x417283CE,	0x589C1D30, 0xD4EC5874, 0xED442EE2, 0x4EFC44BF, 0xD00F5233, 0x2922A076, 0x6D5E64BC, 0x22F8AAD5,
			0xEC423536, 0x9E8427DF, 0x1BE31915, 0x938D9873, 0xF7419DAC, 0x3F33751E, 0x566E24F5, 0xFE767451,	0x267AB7F3, 0xDDD63633, 0xF82BDD81, 0xBEF22F07, 0x7035A0DE, 0xF60D20EE, 0x937FF074, 0xEEB56776,
            0x8B8F2FEB, 0x22FD7813, 0x6C984104, 0xCE54C5AD, 0xD10980DA, 0x6AED74E8, 0xE0AFC8D2, 0xC67320A8,	0x6B47A8CB, 0xC91BEEB4, 0x46A544A7, 0xC3642BAE, 0x1647948D, 0x40AE66E1, 0x7FD18D2B, 0x1187D9EC,
			0xF266FB23, 0xF086E629, 0x54796706, 0xB430F744, 0x1BB31ECF, 0x030CEA0C, 0xBE265DCC, 0x08A796B6,	0xF2DBE3D4, 0xEC86EB7B, 0xBE8C087E, 0x4AD9546A, 0x9523ADC9, 0x0BE75993, 0xD7ACC282, 0x78B0A29B,
            0xA67D2035, 0x61475FE7, 0x195431DE, 0x037942A5, 0x80379883, 0xF79BB3EB, 0xEEF38BCC, 0x60D6DAA3,	0x24FB729E, 0x22CA35C0, 0xD03EA9CE, 0x8BEEDB59, 0x6C636E3A, 0x43543F81, 0x619F3A4C, 0x3B96F79F,
			0xBF4DDD26, 0x463B9627, 0x125BC5D9, 0xB92E34F7, 0x2061CD0D, 0xFDAD061E, 0x47FBF96F, 0x529C8B43,	0xE0B7E4EC, 0x97808D34, 0xADBD5DDC, 0xE9075D64, 0xC1374BF3, 0x35EBC8E4, 0xFB91FC2C, 0xE06D7758,
            0x3FC88817, 0x5A8A79F5, 0x87C36B90, 0xBDE87123, 0xDA5754AC, 0x71F091FF, 0x14FA8081, 0x58B6896A,	0x6831375D, 0x847CA64E, 0xD86C7E87, 0x523BF779, 0x8E8E2F36, 0x734769AD, 0xE594A691, 0x37F8E094,
			0x5352BB5A, 0xC7DF8531, 0x1BAFE32F, 0x79C2F0BC, 0xF42D54A8, 0xD1C71DF9, 0x2407C40D, 0x07F54A03,	0x1D665995, 0x3A635E6D, 0x581BEC2B, 0x5866EE6F, 0x3F41D906, 0x2CEFA5ED, 0x21D4A2A1, 0xBFC4DBD5,
            0x4A86FB09, 0x7566CBE8, 0x954A81B9, 0x4B5D98AE, 0x0544646D, 0x33DA94D2, 0x196AE8A4, 0x2ABEC239,	0x6D58C425, 0xFF65305B, 0x030BA062, 0xE3312A2E, 0x8898312A, 0x864FCCC5, 0x87104720, 0xEFBB34AE,
			0x8AE60DC4, 0x6090A8A0, 0x510F83A7, 0x04E9C5B9, 0x7EA1B2C5, 0x6D730DFA, 0xE343C431, 0x95A48C2D,	0x1BF56A8D, 0x625DE7BB, 0xC4F1784F, 0x076736CD, 0xBB49A028, 0x4CF55602, 0x837580F0, 0xE895697C,
            0x2DACD028, 0x82B8A034, 0x823FDC3D, 0x6C548864, 0x7943D673, 0x5FC6A308, 0xDF64B357, 0xF671992B,	0x009C1DC6, 0x3CF826D2, 0x9851A3E6, 0xF66EA503, 0x421E20EC, 0xA16CEB7D, 0x605E07FA, 0x9C111840,
			0xEAF497F4, 0xC258FF2C, 0xC9C354A2, 0x4A29A029, 0x4ADCD0E1, 0xA9A1E107, 0x21749442, 0x9C02B1FE,	0x76AC0573, 0x75D5C48C, 0x61E36D94, 0x7AF91F17, 0xFC9310A4, 0xF478540E, 0xF7D7C92D, 0x3D643759,
            0xAC67FDE2, 0xA4EA4AF3, 0x7D52A078, 0x82A3DC1C, 0x9D2D3101, 0x8E469114, 0x695B7378, 0x336FAD0A,	0x52C45B4A, 0xFA9CE0E8, 0x4A06D345, 0xEDC13B6B, 0x617193EF, 0x2B8F4C9B, 0x54A22C67, 0x01F63A0C,
			0xEFC65EE6, 0x49F22E3A, 0x0F86257C, 0x7BC4B41C, 0x2517F018, 0x06771EC0, 0x8B8519F1, 0xA7838C19,	0x7AD7B47C, 0xE19E626D, 0x484BF695, 0xDFCC41CE, 0xAB2F5584, 0x732F2598, 0x48151930, 0x7D194D5D,
            0x42914ABC, 0x598ADB14, 0xEA7E59B2, 0xA70566FA, 0x148433F6, 0xFA1D0515, 0x8732EF4E, 0x5FAFE97B,	0x3786D698, 0xD6C43D1D, 0xCCEC2298, 0x26F2BCA3, 0x5951A909, 0xC4419DD2, 0x95BB084F, 0x961879F9,
			0x9155E360, 0x0434AB68, 0x4864FC6F, 0x1B45B406, 0x601D4AA0, 0x41A1CA70, 0xBF0B4E88, 0xDA6B8B19,	0x61BAD167, 0x8D1BB4CC, 0x7669D2AC, 0xFA4AAF2A, 0x28732514, 0xEDB181F0, 0xFF2D27B0, 0xE21D374F,
            0x06506566, 0xEE18C1D8, 0xC9DEB7D1, 0x3BEE1EBA, 0x19DDEA44, 0x1DA45F84, 0x6EE5D188, 0x39A83016,	0x2DDEED1E, 0x20C5DD9F, 0xD98A92F8, 0x0B345233, 0xFF527AFE, 0xB8C334AC, 0x717BA6FA, 0xB3D78DE4,
			0x9A15014F, 0x2A91DC68, 0x11B3631D, 0x8221CDB4, 0x9DC16189, 0x802D7239, 0xA2F09DA3, 0x9CFC0C95,	0xB7A8B9E5, 0x6A19ED2C, 0xAD6EE69D, 0x00B24457, 0x333CD305, 0x221E42E4, 0xA35194A3, 0x28477D4E,
            0x93A5D9D9, 0x04F8EE8E, 0x08B7E891, 0x6A24D951, 0xB663F6E1, 0x83A0CE96, 0xD35D7893, 0xC61B9169,	0x587F9C04, 0x673885E0, 0xA2801FA1, 0xA3102D8F, 0xAF807034, 0xBCEF6E14, 0x069481E4, 0x37DA8EAA,
			0x27D82CD9, 0xDE63400D, 0xD624C0DD, 0x8A9DCBD9, 0x1FE0A5C6, 0x6879114E, 0x402A104D, 0xC426E85E,	0x6004D364, 0x5BF98CFD, 0xA9756183, 0xA3068F7F, 0x5D59AE85, 0xC7135BD9, 0x04364F0C, 0xBBD0F407,
            0xDBBCB71A, 0x36CA3EEB, 0xC310A521, 0xCA749EEE, 0x9140B525, 0xA6D2F3EF, 0x40E5651A, 0x9CA5B1D3,	0x783AA203, 0x8EDCF74E, 0xD9A41B1D, 0x03C9E016, 0x8F60EEEC, 0xD2ABC7A4, 0x028E26D7, 0x72A4D7BB,
			0xA2A3434C, 0xDDDE468A, 0xC5D407C0, 0xF12F3AB8, 0x860A519C, 0x50FDC54C, 0xD7713D4F, 0x937E7B8D,	0xBC13FBF5, 0xE49CA7A0, 0x020E61D5, 0x1D4DBB9B, 0xD0BFB17D, 0x18413201, 0x9A9B9300, 0xC626DFEA,
            0x212FF4DA, 0x3C08A04C, 0x78B51C18, 0xFB9ED56C, 0xAEDD9E7A, 0x04E15B69, 0xF6B7C630, 0x5825BBEC,	0xB32D2853, 0x714AD505, 0x7F52D722, 0x1BEC66A0, 0xFDC34959, 0xCE7D1EA0, 0x669A29D7, 0x5359FEEE,
			0xD1702857, 0xF8E2B961, 0x9DFCA167, 0x123F417D, 0x39F88FDE, 0x43211079, 0x30AC2463, 0x4230D346,	0xCA0D5E6F, 0x00BB15D3, 0x2CE10A03, 0x4DC0A060, 0x76ED8B72, 0x600587C2, 0x0B565710, 0x4EC45B71,
            0xF4202FE6, 0x42B9540C, 0xD4406BE8, 0x4AE6E8FA, 0x94AB046D, 0xCEF817D9, 0xE239E936, 0xC3F0F064,	0x24A226C2, 0x9A5F9F5A, 0x21893116, 0x0049C50F, 0xA910ACF2, 0x427C9680, 0x8045BE8D, 0xF48FAC6A,
			0xED37AB04, 0x408A5529, 0x91C37381, 0xA0879F04, 0xD8778438, 0x18D6DB1C, 0x74A2F5F1, 0xD0CF45B1,	0xBFDF30F0, 0x7A211185, 0x457BF597, 0x0038F390, 0xF570702D, 0xE3240D59, 0xE2AABDEC, 0x9F02488E,
            0x66D272D5, 0xFC529643, 0x20B14166, 0x4357B78A, 0x024D224A, 0xF3B818ED, 0xCFF5AED3, 0xBF299FA3,	0xFF470F97, 0xE9EE2898, 0x87AA4992, 0xD5E73B27, 0xF9CBE6F2, 0x25EF2A51, 0x4D8E8862, 0xA2D77326,
			0x2B5E59B0, 0xB7B2AFC2, 0xA4FF0AF2, 0xD1D04659, 0x89AF8933, 0x0D95C732, 0xBFFF5A86, 0x869FE082,	0x82122A40, 0x262A8642, 0xB0666DAF, 0x75569AB9, 0x131755FC, 0x83F75BEE, 0x6C21FCD9, 0xA80C9495,
            0xEA1F4310, 0x21185550, 0x9A2B88AB, 0x7D33F01E, 0x254584C0, 0x86D6C90D, 0x993C71AE, 0xCFF305DC,	0xA7ED85F1, 0xFCC251C4, 0xB22E3BF1, 0xC1A4D0A8, 0xA1986AD6, 0x761061DB, 0x08D77D0E, 0x3F9B0174,
			0x5D10DF6B, 0x2544C22A, 0x2AAAADA3, 0x5515F9E8, 0x49D2E6B9, 0x6D57C1BA, 0xBE50E43C, 0x19745D3E,	0x8339D08D, 0xE8A11E20, 0x7CB7D882, 0x0680C062, 0x52DCD38F, 0x7FB9F792, 0x9EE2616C, 0x116DE1CC,
            0x9658EABA, 0xEE983490, 0x58C7B453, 0x1BF91CBE, 0x77395E2A, 0xEAED9FA3, 0xBF907C49, 0x447117F0,	0x3DF81781, 0x404EE885, 0xD673208E, 0xF3F55323, 0x4119AAE7, 0x32DBC2FD, 0x060DCF25, 0x499DD4F8,
			0x864CAD86, 0x8FF5710B, 0x5ECBFE1A, 0x6B57DD5E, 0xC615ECF8, 0x349CF46E, 0x6E503E7C, 0xEB3E812C,	0xBEE85608, 0xCD6635D8, 0x1E0888B9, 0x204C3403, 0xC7A07393, 0x06E6AFCB, 0x8E2CC2A2, 0x86D1EC6E,
            0xF46F70A8, 0xE6EA6F24, 0x34F75C2D, 0x890805D2, 0xA86642F2, 0xC552A040, 0x6AFF3BB1, 0xBC336918,	0x690E574C, 0xEB8B142B, 0x8B073DFF, 0x35B824CF, 0xD2D179A8, 0x70875285, 0x607D97B9, 0x4091A77D,
			0xF3E8D1B5, 0xD30D5454, 0xA492020A, 0xA80ED3EB, 0x1AFA7F91, 0x479C6C57, 0xEF802B28, 0xF3F6816E,	0xB6AA0A1A, 0xE3F4B451, 0x90BA80FC, 0x56BBBD46, 0x1188FF46, 0x38D33EC7, 0x51FEFA9B, 0x4D6C74A2,
            0x6E08F5AF, 0x29AB4F50, 0x9ABEC30E, 0xE3DD5CCA, 0x0D26EA4F, 0xBA4E9E61, 0xD777208D, 0xE54266C4,	0xA46BC807, 0x98DB72E1, 0xC5F9898C, 0x00712EB5, 0xE53900B6, 0xB39EC825, 0xE09B8683, 0x581BED5A,
			0x3ABC4757, 0xA4AC46A8, 0xBB1C1101, 0x345B3B2A, 0x70F0BBB4, 0xB97F06E4, 0x0117D08C, 0xA7610D0D,	0xA66C408B, 0xD2CF58EF, 0x30415096, 0xB8622FAD, 0xBA8BAC04, 0x1EF99A50, 0x7288D27F, 0x67159CC7,
            0x613E99A9, 0xF8A2346D, 0xA40128CD, 0x9946CD87, 0x94B00AAE, 0x30BCE8E2, 0xD7EEE6C0, 0x0A84A5B2,	0x6946303C, 0xA84774FD, 0xD3B1DF9E, 0x395B7E53, 0x77147095, 0xEAFFCC34, 0xCDD2BBE2, 0x011F1A94,
			0x6CD13B26, 0x1B8FFE1C, 0xE0F66B40, 0x7030B9E5, 0x553DDB13, 0x1A7FF3B2, 0xEE023FCB, 0x769C4478,	0xD17F9314, 0x99738ABC, 0x97F4F5AD, 0xF8C33414, 0x3E115EF3, 0x5467CD52, 0xF137FBD6, 0x2BA445D3,
            0xC6FD5881, 0xC7A50B2F, 0x8146831A, 0x0CDEA907, 0xE64A63B7, 0x799E0B77, 0xD0FFAB59, 0x8CE38FD1,	0x74A5FD5A, 0x54337714, 0x3CD9EAA3, 0x39B7DFF4, 0x36BDBE65, 0x0FCCF48E, 0xF1990ECC, 0x4178BC1A,
			0x0738FDD3, 0x561D2E20, 0x8DA56F5A, 0xBAC1BBDC, 0x97FFF134, 0x8DC14DEF, 0xAD38AFC6, 0x17A8E263,	0xE4E2A486, 0x41B1B054, 0x28B5B48B, 0xB02F7DC9, 0x7A997789, 0x4CD42926, 0x78925149, 0xE6677761,
            0x6BD73933, 0x20CECBAE, 0x52DC16DD, 0x030C5A59, 0xD8E703DA, 0x16FB4E02, 0x4B913CAC, 0x8A276146,	0x2F0AF574, 0xF9261AA5, 0xA2A3812B, 0xA7073B3E, 0x5A3A575F, 0xB0632A8E, 0x3419CDAA, 0x04985449,
			0x25326204, 0x5BDD94D3, 0x55B97FDE, 0x634ABF77, 0xEB56EEE2, 0x8FB02A76, 0xDEA1D92C, 0x71EF5708,	0x3A37EAAF, 0xEE95DA9F, 0x50511E61, 0xB1724E72, 0x8B35EB53, 0x8D801FA5, 0x0842295B, 0x10E872A4,
            0x6060DB24, 0xF3715E6F, 0xD6616678, 0x9E92981B, 0x58E46A58, 0xD0471C65, 0x6C340711, 0x3D25E049,	0x02A58A4E, 0xDB6CEBED, 0x502525D7, 0x21A809CD, 0x2C64277E, 0xAC140F28, 0xAFAF698A, 0x9F7ABCE0,
			0xE5CEC388, 0x3DDEA66A, 0xD0E82916, 0xC3ABD7E6, 0x44916DB5, 0x7B9FCD16, 0xEE32E584, 0x7DC53AF9,	0x32198E7C, 0x3B542D80, 0xAE1D5468, 0x5B157463, 0x9D885FF6, 0xD3D4E014, 0x9E64C1E1, 0xB7095BCA,
            0x40E8588C, 0xB0F55B9A, 0xF2B8DC96, 0x2995A365, 0x14B48666, 0xF0D9B319, 0x552BA8F3, 0x1A13FDDD,	0xFCC9A756, 0x6FC557D0, 0x114E14FB, 0x32234998, 0x463C0E37, 0xC7CD8FB7, 0xCC9F00A4, 0x7F7E9E43,
			0x5FCD1504, 0x7F9A43D8, 0x241BD482, 0xC5A3F39A, 0x7F2BBB35, 0x5734D187, 0x0B51E2AE, 0x51855521,	0x243E46FB, 0x86E99AD8, 0x4A3B06F9, 0xC5BF933C, 0x69DB984C, 0x18122CC2, 0x1310028E, 0x6AB43D98,
            0x8BB874E4, 0xABA7BD1C, 0xB9DA43FB, 0x3490803B, 0x893FF01E, 0x189DFF90, 0x905D9DD5, 0x6E4EFF2F,	0xD588FDC6, 0x2E555530, 0x8DB2CC2C, 0x73A2A652, 0x1EFF0F6E, 0xC1CA1D1D, 0xB7EA63B6, 0xC21513BA,
			0x03FCF67A, 0x0E8C6BB2, 0xEC093701, 0xD4204DA5, 0xEF61E80F, 0x4C244F35, 0x89B2ABA1, 0x35FB4E00,	0x57242434, 0x52D776B1, 0x20ED2BF4, 0x88FC5505, 0x4F64A620, 0x7AC3B93F, 0x746C798E, 0x7F7676E2,
            0xB5D9BE09, 0xC84223E9, 0x371A5492, 0x7BF18FE3, 0x4E54C64F, 0x92133E3D, 0x8DA5E2A8, 0x34FABD24,	0xD686AED1, 0x96322F0D, 0x66EF4647, 0x247D8711, 0xE027FEB1, 0xE550FDC4, 0x1C3AA4B5, 0xFE757095,
			0xC3DBB8BF, 0x41F086BC, 0xB6BF6546, 0x87F7D580, 0xF36567A0, 0x82832A0C, 0x25CBDBEE, 0x019EEF1A,	0x31507570, 0x5A80705C, 0xAAC931A5, 0xF5C543BF, 0xB71D6BB6, 0x00798F0A, 0xF655BC5C, 0x81E2C701,
            0x083475E9, 0x51864108, 0x1738790D, 0x43B76C33, 0xC600C83E, 0x68E8B07D, 0x023A5703, 0x308F2697,	0xDA57A706, 0x0F0FCC83, 0x774A616F, 0xB8378F80, 0x10E597D8, 0xCDBD262B, 0x209AA36A, 0x28114B2E,
			0x5C4C77E7, 0x66B96ABA, 0x961FD730, 0x8F35074D, 0x09E34CE2, 0x9AB5BBD2, 0xF85EEB4E, 0xC038AE8C,	0xDC85A1F6, 0xD158DA88, 0x544B0FEB, 0xB4A57FE7, 0xC2750EE3, 0x267A96BD, 0xC61A6DFA, 0xF651E2CF,
            0x268B4BB1, 0xB1D23421, 0xD187D0C0, 0xC83C6646, 0xE2C8092E, 0x67452CBA, 0x427085BB, 0x049025DA,	0x96D07DC2, 0x973E194C, 0x3844E91E, 0xD0735FD5, 0x07267AEC, 0x7D993A1E, 0x3A24871B, 0x2AC9E353,
			0x53F3DD71, 0xF5A51628, 0xC3A6590A, 0x45D6B7B4, 0x4D10F14E, 0x88AF48F1, 0xC05B18DE, 0x0FF022C9,	0xB3DECEEE, 0xFFD025D0, 0xA1B1A182, 0xC60A0F66, 0x417B41B2, 0x5103B4C7, 0x88FC728B, 0x51848EA3,
            0x450954A1, 0x73C2EA00, 0xCEBADC6E, 0xA33F0AC9, 0x6A7AA328, 0xEDD3E04C, 0xAF564B46, 0x9269A21B,	0xFA854B1B, 0x61D912BA, 0x2BD53B1D, 0x2545A86C, 0x0DBACA25, 0x42592962, 0xDB83F3A4, 0x7CBA45C3,
			0xA75DDD7B, 0xB45C8CD2, 0x9629F4D5, 0x098F8AE3, 0x218BC7B9, 0xF8512BA5, 0xF9058F9F, 0x4AEE3E36,	0x6DCB73CA, 0xBA642596, 0xD91630ED, 0x5AEFF837, 0x8A69C9AA, 0xA1420321, 0x42C198FA, 0xAC55A5D4,
            0x96AFA270, 0x0A8D28F0, 0x0EDC82CB, 0x8DD9BD79, 0x0CCFA245, 0xA13895C9, 0x206FB3E3, 0xB0222EAE,	0xBF2C74F8, 0xF82A1ECA, 0xAF2BCC10, 0xDA4F1FCF, 0x31AC03E5, 0xA27D2E98, 0x2CA38131, 0xA2FE3639,
			0xDBFCF1DA, 0x663E2241, 0x6DA76945, 0x6073CDFD, 0xDD19BC20, 0xAE5AA5AB, 0x8896EC32, 0x2C874CF2,	0x5176BB43, 0xA35321D8, 0xD8D45C62, 0xCA17F1C3, 0xBCE81D04, 0x6C5BDE2D, 0x96382B52, 0x9E91975B,
            0x8A20E601, 0x4E8D0A8E, 0xB912AEBE, 0x2F3A7213, 0xCF7F91E5, 0xA3551238, 0x232600F5, 0x4CD22286,	0x69EB2911, 0x57DC3614, 0x5E845CF3, 0x921905FF, 0x1DAF12ED, 0x7202DF88, 0x5BCC277F, 0x113C2CE3,
			0x1D05A3BA, 0x2CB008BF, 0x4D92F469, 0x886013DB, 0x1801356C, 0x66B14C09, 0x744DB6F2, 0x6D3C04DA,	0xD2FB5C0E, 0x99BA95AD, 0x5109ED3B, 0x0A8FBC1A, 0x26C0CF11, 0xBB90310E, 0xA9D26207, 0x77FB1074,
            0x53AA2EDE, 0xD0DC2714, 0xFB879A48, 0xCBB73BE0, 0x3E053B41, 0xD1A2CCA8, 0x35B980EC, 0x1945231C,	0xCE06F753, 0xE1F0DBEB, 0x3C4C1F79, 0x087EFCA6, 0x1FFEC337, 0xD4E76DF4, 0xF2607D9A, 0x4E2A7CBB,
			0x7150D445, 0xC5D7F239, 0x87E963E3, 0x7B77DEEF, 0x4DED2073, 0x0FD7E8D5, 0xF506A118, 0x3161D204,	0x822D436F, 0xBA0798DC, 0xEA8B62EA, 0xCA224A96, 0x7F6B6F55, 0xAFEE1CEC, 0x9915BDB8, 0x0AC2FEC6,
            0xF9107B3D, 0x9977BAAA, 0x614A38F5, 0x330E6A9D, 0xCB21B474, 0x4E52DB36, 0xDEB898EE, 0x8ABAB806,	0xB9AA328C, 0x2F1C8968, 0xDB4D72E9, 0x10F6F472, 0x47C3A645, 0x2D704E5C, 0x82322656, 0x741DC4E0,
			0x4A271DD5, 0x17C8BD5A, 0x05602A04, 0x23121218, 0x729F9617, 0x2049AD71, 0xEA0F2891, 0x72B38D2F, 0xC68A145D, 0xB3963D89, 0xF2D0B4E7, 0xDF34A2E9, 0x0B4713C3, 0xDEC352E4, 0xD9C23728, 0x3F543672,
            0xD555B0C7, 0xE80F63BB, 0x02B3C591, 0xA00D334E, 0x1223A826, 0xE22D67BA, 0x93D2844A, 0xFC84CED3,	0x3C3BB2E3, 0xBEEDCF89, 0x1E930813, 0xE35AF794, 0x358682E8, 0x455FD9F2, 0x9423D1FB, 0xA6D1FA49,
			0x42FE2223, 0x2FDD690D, 0x3743260D, 0xC6181549, 0x972F1052, 0xC5BDB0DA, 0x0B2E04DC, 0x85602C7E,	0xABE23CB2, 0xF7083E28, 0x28EBD42F, 0xD9F81924, 0x2B94225C, 0xE9DC1327, 0x9B4DE0D9, 0xF2821627,
            0x138A6F03, 0xF6C467B3, 0x867BB627, 0xEE529FFC, 0xCEA5D764, 0xB1BB16B1, 0x5E76E959, 0x8C511039,	0x78A81CFA, 0xE5C22B73, 0x5F7A13DB, 0x20351DF1, 0x83FACF34, 0x14C50CA3, 0x2725CFA5, 0x075FFC53,
			0xC75D5B0E, 0x965AD2E5, 0xA9BA35F6, 0x85265CC9, 0xACB0F6EE, 0x014EE921, 0x0DA5B2C4, 0x684B921A,	0xD9F60AB7, 0x3D33E15A, 0x6D1AD72A, 0xFBD4C1ED, 0x0594C776, 0x0DA58C8D, 0xD6978AE5, 0xE0F19AFB,
            0xD4197E9B, 0xC9C7C58A, 0xFBD084D9, 0x4E9A65FB, 0x60B84C0C, 0x7CE8CCBD, 0x443F2A5C, 0x07EE8BD0,	0x9DCD6100, 0xAAE83AE2, 0xEA1E1692, 0x1470988C, 0x06A7FDD7, 0x27E4FEED, 0x5B38431B, 0x42CE6B33,
			0xA5EADEEE, 0x4037E735, 0x60634465, 0x3BB96516, 0x48189628, 0xB7346959, 0x60FB854C, 0xFD27358D,	0x262B2FB3, 0x763AF1F0, 0x942E4B95, 0x98C42FAC, 0x874AD7C2, 0x80E2D539, 0xC7772DD6, 0x29C14FC8,
            0x95C5D8BD, 0x844EC8D7, 0x8F2D5265, 0xFE77D970, 0x6F9BDB8E, 0xC7F3B8FA, 0x821B1FFC, 0xA3AD0F15,	0x894911F8, 0xBCD2216B, 0x8FABF901, 0xBAAABCC3, 0xCA412E85, 0x177394C1, 0x098EC1AD, 0xE7793255,
			0x74C5D8D8, 0x6F31DD75, 0xB861E19E, 0x35335173, 0x073213EA, 0x187EE794, 0x8851A470, 0x57FACCFB,	0x4DA78D22, 0x84A5E45C, 0x4E39C4F1, 0xEA0805DB, 0xA7417375, 0x87773287, 0x0C557441, 0x791D4CEE,
            0x8F71A9AB, 0x42C65A0B, 0x86F1FB70, 0x43D911F0, 0xB4512955, 0x411DDA22, 0x44B2C5B5, 0x8A4ED1A1,	0x660E8EE8, 0xB326C06C, 0x378ED76B, 0xA69CEBA8, 0x55E6B72B, 0xF39C03A1, 0x4F8F27E9, 0x8C7C597B,
			0xFDA52E2F, 0x5D824AED, 0x762EAF08, 0x05199051, 0xA9E2529E, 0xBC7F40EB, 0x9F754C56, 0x620BC5C0,	0xB254F4C1, 0x7D70972C, 0xF109FC14, 0xEEB8CB29, 0x80756543, 0x42F51CA9, 0xA47DA5DC, 0xDD4C35C5,
            0xDF6DE915, 0x87F53336, 0xEA3A3626, 0xBD2F7D9D, 0xFD7BE573, 0xBBAAAA18, 0x386DC3AE, 0x742EE4C6,	0xA6201C16, 0xE6AA6CA4, 0xDD111FE9, 0x297534C2, 0xD57DEA57, 0xA8DF102E, 0x33BB9317, 0x086C3C4E,
			0x60519721, 0x392E1B53, 0x96303DE5, 0x40D2468C, 0xD9BED879, 0x156265E6, 0x2D133A76, 0x3AD9ACE1,	0x3A06FCB7, 0x0D97E84D, 0xAB8A3DD6, 0x2D24EB1D, 0x27AC99D0, 0x019477A5, 0x3E60BCBF, 0xC40D4425,
            0x1BCB4357, 0xCE87BFA3, 0x5C75C331, 0x80CDDA70, 0xCFFE462A, 0x9FE41D88, 0xFA29C22E, 0x75B33322,	0x7F9EA699, 0x6F31CD35, 0x48A5CA08, 0x1E14C2B3, 0x399B3456, 0xE8DBCCCA, 0xE0C3D71C, 0x99B80894,
			0x1E795966, 0x8A8ACD8A, 0x5C632673, 0x64C44F69, 0x7050F6B1, 0xD5C9ACBE, 0xA0D0D8F2, 0x0B7168B4,	0x52A22A4D, 0xE917DCBF, 0x5998A5EA, 0x6AC65D11, 0xA98A85F1, 0x8B7BE88A, 0x7527637C, 0xE7D60189,
            0x6E69FFAA, 0xD115B178, 0xF655EFC4, 0xF3BAD78A, 0xFA81BF9F, 0xAC1881B4, 0x5D5A74D9, 0xDB4E64F6,	0xB1EC1844, 0x13864BF6, 0xC93A8D28, 0xE45F1F91, 0x973213BE, 0x988EEE26, 0x1ED8C2AE, 0x57F007CD,
			0x87A39527, 0x3FFC2072, 0x8F82A5BB, 0x3578687E, 0xC8149BF4, 0x36ECB610, 0xFC044A1D, 0x7F69C2A7,	0xF28C6FC9, 0xFA3C483C, 0xBF8DB013, 0xDC856676, 0x60B98D28, 0x9EFDD265, 0xFBDC5F32, 0xD1D35DFB,
            0x4E3595F9, 0x1116DAE3, 0xD11678A6, 0x08C6CBB4, 0x44059F2C, 0xC739889F, 0x04187A3F, 0xD2462954,	0x9D9F66F6, 0x04ECA5A6, 0xD5F25077, 0x75BFAED8, 0xC189A2DD, 0x9EFAA7E4, 0x0F4D5DC1, 0xED7328F4,
			0x905978A5, 0x383609D0, 0x9AA26D07, 0xC88EDD26, 0x15F12F5B, 0x1090455F, 0x0B85DE45, 0x4181B5DF,	0x3AFE1280, 0x059AA558, 0x28534255, 0x01DCB829, 0xB112909D, 0x4DEF0002, 0x57ACCF3C, 0x793525C0,
            0x0204A9AF, 0xCE454A9A, 0xE49AE322, 0x81707968, 0xC87E7338, 0xB775FB96, 0xF57E0360, 0xE8FB020F,	0x17C089CB, 0x2E18A1A3, 0x04251C26, 0x03F29AAA, 0xB9E291DC, 0x55EDD914, 0xE3826CBB, 0xE2278E3E,
			0x4862A221, 0xC0135EDF, 0xC1DA6E1B, 0xB78D2161, 0xDDBB6D10, 0x3D102593, 0x7AFDC8B1, 0x85D0D60A,	0x6F9E43F6, 0xE0752045, 0x5E7E1B56, 0xB6899A3C, 0x4FA21007, 0xAD53C90A, 0x1E33B83F, 0x6426B760,
            0x13F2EA5F, 0x006E2B71, 0xB03A41EE, 0xF3B2EB3F, 0x999D2AF8, 0x8D2C6656, 0x2E1ABD3B, 0x7DA5CEFC,	0x60D36AA3, 0x965C8734, 0x6AD0D853, 0xB93D248F, 0x0E58D231, 0xD7797AEE, 0x628C9BC3, 0xA4BBB4F0,
			0xC080C6E0, 0x454088DD, 0x03203E6D, 0x2005E1B8, 0xF7A6DDF9, 0xDB820DF2, 0x45A2E231, 0xBE0BCF8D,	0x35923B66, 0x422C2292, 0xE2CC0C18, 0x03F48BEB, 0x0701C163, 0x25D019D1, 0x88A74C7B, 0x7E9CB72E
        };
        private static Single[] CONST_TABLE_SINGLE = {
            0.120002f, 0.986570f, 0.722385f, 0.167307f, 0.010990f, 0.694510f, 0.783851f, 0.676534f, 0.205887f, 0.347737f, 0.686114f, 0.434551f, 0.302053f, 0.549133f, 0.225536f, 0.483361f,
			0.693883f, 0.799498f, 0.065586f, 0.671937f, 0.693111f, 0.246235f, 0.607265f, 0.353497f, 0.501309f, 0.988425f, 0.338359f, 0.154900f, 0.481250f, 0.310782f, 0.786255f, 0.167610f,
            0.010879f, 0.803485f, 0.148728f, 0.791803f, 0.608308f, 0.803640f, 0.774651f, 0.249656f, 0.317713f, 0.995945f, 0.053474f, 0.875161f, 0.073479f, 0.665095f, 0.436491f, 0.140379f,
			0.104735f, 0.397575f, 0.312075f, 0.119031f, 0.707183f, 0.209307f, 0.555252f, 0.578763f,	0.505198f, 0.212205f, 0.838087f, 0.208028f, 0.054213f, 0.866434f, 0.023573f, 0.551242f,
            0.687173f, 0.999776f, 0.127175f, 0.590792f, 0.188830f, 0.469513f, 0.778861f, 0.043963f, 0.795599f, 0.045703f, 0.788270f, 0.151467f, 0.698835f, 0.570437f, 0.362270f, 0.721216f,
			0.232438f, 0.599510f, 0.612420f, 0.075392f, 0.555247f, 0.906975f, 0.087032f, 0.354485f, 0.353827f, 0.704468f, 0.135991f, 0.822222f, 0.570476f, 0.163423f, 0.241411f, 0.101961f,
            0.311846f, 0.105938f, 0.842825f, 0.248156f, 0.449225f, 0.334440f, 0.293060f, 0.600503f, 0.846563f, 0.009280f, 0.500843f, 0.865518f, 0.929474f, 0.735143f, 0.665305f, 0.922422f,
			0.183777f, 0.044452f, 0.622688f, 0.766084f, 0.312358f, 0.980205f, 0.887642f, 0.764080f, 0.867501f, 0.449869f, 0.807114f, 0.290191f, 0.925427f, 0.173148f, 0.997635f, 0.993771f,
            0.611437f, 0.131459f, 0.653396f, 0.813207f, 0.456944f, 0.514304f, 0.236047f, 0.166515f, 0.020011f, 0.524717f, 0.429768f, 0.817708f, 0.253891f, 0.213298f, 0.417906f, 0.054997f,
			0.318964f, 0.529712f, 0.947010f, 0.841350f, 0.487772f, 0.133649f, 0.510377f, 0.590153f, 0.819746f, 0.251308f, 0.972948f, 0.162748f, 0.473510f, 0.609674f, 0.889498f, 0.179319f,
            0.827368f, 0.513489f, 0.663464f, 0.378637f, 0.354773f, 0.281231f, 0.820133f, 0.660887f, 0.297914f, 0.032999f, 0.462859f, 0.691380f, 0.318225f, 0.400367f, 0.250773f, 0.248883f,
			0.695674f, 0.124958f, 0.654058f, 0.196053f, 0.196653f, 0.475930f, 0.911402f, 0.548731f, 0.153614f, 0.061774f, 0.852120f, 0.518542f, 0.340984f, 0.354861f, 0.990926f, 0.624899f,
            0.803417f, 0.809167f, 0.308746f, 0.310905f, 0.698262f, 0.744097f, 0.466135f, 0.483785f, 0.177757f, 0.158458f, 0.819099f, 0.748385f, 0.399824f, 0.380361f, 0.602337f, 0.788164f,
			0.281967f, 0.705247f, 0.337670f, 0.490979f, 0.810020f, 0.942710f, 0.662162f, 0.884471f, 0.289301f, 0.516163f, 0.854984f, 0.877986f, 0.916020f, 0.874113f, 0.452517f, 0.407640f,
            0.719035f, 0.851573f, 0.057344f, 0.140063f, 0.640263f, 0.381708f, 0.355195f, 0.778383f, 0.433308f, 0.193769f, 0.976015f, 0.716333f, 0.148395f, 0.100628f, 0.993516f, 0.508050f,
			0.620064f, 0.001387f, 0.687586f, 0.443134f, 0.189176f, 0.714220f, 0.963902f, 0.980456f, 0.669406f, 0.900197f, 0.287189f, 0.060730f, 0.509840f, 0.668257f, 0.299952f, 0.684697f,
            0.826618f, 0.391160f, 0.606379f, 0.038100f, 0.209295f, 0.585779f, 0.709128f, 0.129369f, 0.213820f, 0.283771f, 0.992532f, 0.686462f, 0.033045f, 0.576930f, 0.710970f, 0.652294f,
			0.379103f, 0.748257f, 0.094308f, 0.095840f, 0.217317f, 0.427590f, 0.462647f, 0.058243f, 0.265386f, 0.797953f, 0.959500f, 0.932353f, 0.551263f, 0.811848f, 0.248032f, 0.430502f,
            0.552694f, 0.027540f, 0.861143f, 0.740226f, 0.909231f, 0.191622f, 0.547857f, 0.800027f, 0.515813f, 0.527113f, 0.916654f, 0.426449f, 0.929498f, 0.794114f, 0.110347f, 0.959535f,
			0.046415f, 0.522626f, 0.456215f, 0.066983f, 0.190598f, 0.061699f, 0.562589f, 0.465522f, 0.360768f, 0.291910f, 0.463380f, 0.171780f, 0.618347f, 0.130430f, 0.373747f, 0.524876f,
            0.219972f, 0.050438f, 0.554103f, 0.439616f, 0.618392f, 0.336057f, 0.997355f, 0.511438f, 0.718039f, 0.565525f, 0.301845f, 0.053599f, 0.100752f, 0.940145f, 0.336755f, 0.313281f,
			0.749716f, 0.457024f, 0.489461f, 0.995154f, 0.558905f, 0.789992f, 0.885219f, 0.861104f, 0.721828f, 0.951805f, 0.591165f, 0.959943f, 0.913373f, 0.713994f, 0.557417f, 0.618968f,
            0.093441f, 0.625018f, 0.242716f, 0.366283f, 0.688625f, 0.018921f, 0.655444f, 0.936203f, 0.050707f, 0.437183f, 0.825319f, 0.402534f, 0.605613f, 0.031690f, 0.296927f, 0.420746f,
			0.665763f, 0.094288f, 0.744088f, 0.643478f, 0.097653f, 0.401701f, 0.257753f, 0.722117f, 0.836066f, 0.089125f, 0.529057f, 0.076722f, 0.211220f, 0.319876f, 0.113276f, 0.218894f,
            0.476379f, 0.712760f, 0.934030f, 0.150638f, 0.936826f, 0.993880f, 0.026997f, 0.120829f, 0.448385f, 0.498645f, 0.552093f, 0.582173f, 0.325865f, 0.612897f, 0.348103f, 0.008438f,
			0.666603f, 0.393286f, 0.847077f, 0.824343f, 0.464235f, 0.759336f, 0.970596f, 0.039775f, 0.352495f, 0.018027f, 0.249701f, 0.007923f, 0.269311f, 0.188462f, 0.350290f, 0.853159f,
            0.487544f, 0.839413f, 0.217346f, 0.317037f, 0.761763f, 0.578718f, 0.173135f, 0.979067f, 0.609372f, 0.666943f, 0.405516f, 0.861031f, 0.892699f, 0.349853f, 0.885632f, 0.383896f,
			0.530516f, 0.872442f, 0.595547f, 0.670703f, 0.342183f, 0.983106f, 0.836381f, 0.792516f, 0.717325f, 0.748088f, 0.475685f, 0.942691f, 0.130708f, 0.737111f, 0.338823f, 0.733080f,
            0.650368f, 0.144510f, 0.800626f, 0.715457f, 0.653816f, 0.328785f, 0.929258f, 0.894538f, 0.003924f, 0.885098f, 0.733855f, 0.750519f, 0.346421f, 0.144433f, 0.863046f, 0.859112f,
			0.696376f, 0.069311f, 0.763330f, 0.946420f, 0.341518f, 0.873513f, 0.791374f, 0.515297f, 0.915409f, 0.362434f, 0.323563f, 0.305282f, 0.105137f, 0.707088f, 0.474151f, 0.460900f,
            0.290740f, 0.367746f, 0.782522f, 0.796080f, 0.135003f, 0.100633f, 0.339645f, 0.224883f, 0.595760f, 0.590857f, 0.473772f, 0.433406f, 0.928721f, 0.123824f, 0.156834f, 0.597770f,
			0.012124f, 0.339651f, 0.025245f, 0.246018f, 0.184624f, 0.196213f, 0.199811f, 0.066287f, 0.317390f, 0.389556f, 0.767169f, 0.431604f, 0.524109f, 0.926765f, 0.586435f, 0.550840f,
            0.776716f, 0.359135f, 0.396450f, 0.296493f, 0.529848f, 0.942787f, 0.607162f, 0.232137f, 0.174617f, 0.102226f, 0.912111f, 0.058181f, 0.233762f, 0.915126f, 0.224892f, 0.616371f,
			0.535137f, 0.451108f, 0.883883f, 0.194536f, 0.790361f, 0.773570f, 0.858678f, 0.257401f, 0.786370f, 0.920717f, 0.433738f, 0.872105f, 0.420115f, 0.370541f, 0.975352f, 0.435536f,
            0.365997f, 0.489879f, 0.938371f, 0.248519f, 0.876170f, 0.363934f, 0.999874f, 0.751865f, 0.432952f, 0.692442f, 0.869737f, 0.691102f, 0.010402f, 0.620751f, 0.101858f, 0.479382f,
			0.458246f, 0.180050f, 0.235840f, 0.029677f, 0.999473f, 0.341969f, 0.967960f, 0.577141f, 0.680448f, 0.881343f, 0.700808f, 0.419188f, 0.357503f, 0.465610f, 0.863337f, 0.906177f,
            0.749250f, 0.351715f, 0.892973f, 0.536359f, 0.156900f, 0.475524f, 0.149389f, 0.049010f, 0.815921f, 0.169899f, 0.045668f, 0.090182f, 0.527463f, 0.906829f, 0.336572f, 0.850187f,
			0.959254f, 0.577068f, 0.892668f, 0.109671f, 0.925762f, 0.532873f, 0.866745f, 0.415219f, 0.639448f, 0.832368f, 0.340022f, 0.438989f, 0.465326f, 0.223529f, 0.570637f, 0.692969f,
            0.725598f, 0.201707f, 0.367621f, 0.257754f, 0.518111f, 0.585708f, 0.746461f, 0.042664f, 0.074047f, 0.789499f, 0.234358f, 0.724743f, 0.321131f, 0.458094f, 0.522119f, 0.697374f,
			0.959133f, 0.763137f, 0.978587f, 0.916605f, 0.180825f, 0.239547f, 0.680278f, 0.013825f, 0.930638f, 0.205418f, 0.224535f, 0.896607f, 0.667120f, 0.349595f, 0.125859f, 0.512397f,
            0.426326f, 0.010199f, 0.275011f, 0.449391f, 0.772862f, 0.127981f, 0.373988f, 0.866006f, 0.711903f, 0.869965f, 0.675226f, 0.807355f, 0.371364f, 0.123979f, 0.826835f, 0.383044f,
			0.747090f, 0.584562f, 0.563627f, 0.659437f, 0.615979f, 0.528998f, 0.213350f, 0.766427f, 0.837586f, 0.060248f, 0.728395f, 0.583541f, 0.171172f, 0.904832f, 0.585188f, 0.820611f,
            0.551461f, 0.454454f, 0.816739f, 0.876002f, 0.277056f, 0.504007f, 0.584679f, 0.149123f, 0.640541f, 0.101790f, 0.890040f, 0.635295f, 0.561263f, 0.596597f, 0.112678f, 0.561308f,
			0.853859f, 0.912727f, 0.160822f, 0.831493f, 0.035058f, 0.344119f, 0.162440f, 0.664907f, 0.255588f, 0.256051f, 0.130207f, 0.825536f, 0.784795f, 0.124045f, 0.109673f, 0.065989f,
            0.308034f, 0.886062f, 0.354071f, 0.436078f, 0.797756f, 0.855449f, 0.379713f, 0.057957f, 0.903982f, 0.399615f, 0.913404f, 0.636106f, 0.044598f, 0.751650f, 0.694367f, 0.927825f,
			0.453747f, 0.207498f, 0.854304f, 0.601371f, 0.881185f, 0.604513f, 0.433395f, 0.231003f, 0.993774f, 0.807085f, 0.229105f, 0.953038f, 0.913027f, 0.681861f, 0.218833f, 0.529151f,
            0.021921f, 0.169681f, 0.553719f, 0.470817f, 0.343139f, 0.002535f, 0.664554f, 0.681993f, 0.435957f, 0.704932f, 0.400714f, 0.360094f, 0.547646f, 0.364562f, 0.102501f, 0.085478f,
			0.927657f, 0.097240f, 0.141896f, 0.800991f, 0.078370f, 0.215610f, 0.402663f, 0.352820f, 0.518093f, 0.957909f, 0.634363f, 0.408760f, 0.460396f, 0.893591f, 0.102755f, 0.241715f,
            0.490701f, 0.716089f, 0.763738f, 0.786343f, 0.374857f, 0.188357f, 0.062552f, 0.661462f, 0.219753f, 0.570260f, 0.849999f, 0.472318f, 0.914975f, 0.780821f, 0.035887f, 0.563229f,
			0.419139f, 0.683141f, 0.387021f, 0.709123f, 0.439081f, 0.480262f, 0.598132f, 0.216844f, 0.679174f, 0.331792f, 0.383940f, 0.524494f, 0.990679f, 0.218424f, 0.662863f, 0.983709f,
            0.527734f, 0.686873f, 0.278558f, 0.444035f, 0.126664f, 0.696977f, 0.644935f, 0.989073f, 0.064055f, 0.903749f, 0.074100f, 0.349949f, 0.276441f, 0.231981f, 0.920918f, 0.866188f,
			0.357531f, 0.277587f, 0.096888f, 0.199300f, 0.318458f, 0.811627f, 0.281106f, 0.762695f, 0.459685f, 0.905205f, 0.928580f, 0.556512f, 0.440004f, 0.428178f, 0.949810f, 0.547066f,
            0.426352f, 0.872180f, 0.374046f, 0.984505f, 0.530666f, 0.966673f, 0.636951f, 0.342025f, 0.176347f, 0.145098f, 0.291884f, 0.030488f, 0.251644f, 0.486435f, 0.087551f, 0.673293f,
			0.653945f, 0.241107f, 0.459807f, 0.679427f, 0.948328f, 0.723215f, 0.302416f, 0.622505f, 0.170496f, 0.462567f, 0.211817f, 0.457975f, 0.705842f, 0.313443f, 0.077656f, 0.234469f,
            0.530385f, 0.305141f, 0.309641f, 0.887229f, 0.680463f, 0.499106f, 0.407338f, 0.620396f, 0.557837f, 0.816139f, 0.647983f, 0.945608f, 0.503219f, 0.789920f, 0.175639f, 0.059852f,
			0.920080f, 0.372336f, 0.840911f, 0.442902f, 0.253117f, 0.410670f, 0.672973f, 0.812960f, 0.263860f, 0.886724f, 0.090340f, 0.769283f, 0.220811f, 0.395963f, 0.091689f, 0.150708f,
            0.877406f, 0.509291f, 0.217575f, 0.798791f, 0.624284f, 0.600515f, 0.393278f, 0.863545f, 0.520564f, 0.898865f, 0.669052f, 0.356046f, 0.123573f, 0.513277f, 0.823707f, 0.231469f,
			0.457718f, 0.484738f, 0.626221f, 0.913283f, 0.692389f, 0.434730f, 0.193693f, 0.681403f, 0.554125f, 0.354017f, 0.071592f, 0.790042f, 0.128636f, 0.898224f, 0.654333f, 0.619864f,
            0.290047f, 0.852761f, 0.564075f, 0.120653f, 0.306239f, 0.171975f, 0.738536f, 0.408598f, 0.559328f, 0.594541f, 0.726293f, 0.119076f, 0.868816f, 0.106893f, 0.453956f, 0.314137f,
			0.326887f, 0.942957f, 0.898591f, 0.253913f, 0.572603f, 0.448214f, 0.919365f, 0.318901f, 0.180419f, 0.941955f, 0.921956f, 0.645832f, 0.728691f, 0.523701f, 0.365428f, 0.995214f,
            0.526906f, 0.784433f, 0.262390f, 0.210824f, 0.680019f, 0.016790f, 0.798382f, 0.741591f, 0.526619f, 0.119682f, 0.705064f, 0.399281f, 0.124414f, 0.570671f, 0.246688f, 0.780932f,
			0.756333f, 0.302901f, 0.674215f, 0.545509f, 0.756344f, 0.826670f, 0.486270f, 0.237420f, 0.839063f, 0.881132f, 0.110477f, 0.369135f, 0.321745f, 0.221623f, 0.922182f, 0.553665f,
            0.448365f, 0.180597f, 0.358725f, 0.385443f, 0.229263f, 0.187479f, 0.465916f, 0.382005f, 0.197694f, 0.579175f, 0.019774f, 0.387841f, 0.842622f, 0.800190f, 0.081289f, 0.906792f,
			0.818261f, 0.147669f, 0.003351f, 0.766120f, 0.322362f, 0.072180f, 0.393772f, 0.133295f, 0.590757f, 0.542274f, 0.586978f, 0.342958f, 0.715280f, 0.151981f, 0.266779f, 0.992255f,
            0.031093f, 0.869945f, 0.185345f, 0.902529f, 0.997857f, 0.448547f, 0.897103f, 0.015775f, 0.664490f, 0.297734f, 0.508967f, 0.271199f, 0.900406f, 0.660651f, 0.608809f, 0.970906f,
			0.018469f, 0.320515f, 0.168356f, 0.272252f, 0.194543f, 0.256078f, 0.329511f, 0.568999f, 0.400502f, 0.309353f, 0.036654f, 0.589610f, 0.293628f, 0.256678f, 0.137179f, 0.219095f,
            0.032506f, 0.370399f, 0.845197f, 0.893407f, 0.670332f, 0.157858f, 0.244871f, 0.631844f, 0.722434f, 0.104130f, 0.807310f, 0.238061f, 0.183651f, 0.490523f, 0.355103f, 0.240385f,
			0.654307f, 0.877145f, 0.924467f, 0.892574f, 0.547227f, 0.047174f, 0.529869f, 0.924793f, 0.472918f, 0.795681f, 0.228334f, 0.557194f, 0.914181f, 0.571704f, 0.970774f, 0.240121f,
            0.914249f, 0.159595f, 0.569988f, 0.036565f, 0.399545f, 0.381605f, 0.473120f, 0.760659f, 0.826925f, 0.697149f, 0.405972f, 0.576424f, 0.859069f, 0.188879f, 0.837509f, 0.400759f,
			0.192080f, 0.128047f, 0.933052f, 0.923784f, 0.229952f, 0.634019f, 0.968822f, 0.068114f, 0.879766f, 0.852837f, 0.911602f, 0.832852f, 0.775436f, 0.975200f, 0.095518f, 0.329925f,
            0.788719f, 0.335430f, 0.179119f, 0.250983f, 0.004261f, 0.927624f, 0.353950f, 0.982854f, 0.639110f, 0.239533f, 0.745700f, 0.247333f, 0.021626f, 0.555269f, 0.435229f, 0.403799f,
			0.691136f, 0.072296f, 0.711217f, 0.662384f, 0.477593f, 0.297933f, 0.738230f, 0.624050f, 0.183810f, 0.696344f, 0.951219f, 0.804894f, 0.518292f, 0.312568f, 0.566821f, 0.333686f,
            0.826376f, 0.600588f, 0.943854f, 0.872096f, 0.506145f, 0.554640f, 0.250879f, 0.040658f, 0.764201f, 0.102593f, 0.127512f, 0.171628f, 0.308526f, 0.732215f, 0.584398f, 0.511009f,
			0.233104f, 0.210452f, 0.580430f, 0.881668f, 0.741529f, 0.481133f, 0.692388f, 0.893745f, 0.097622f, 0.076859f, 0.744383f, 0.852650f, 0.123302f, 0.149229f, 0.211075f, 0.932942f,
            0.572303f, 0.292906f, 0.455044f, 0.112353f, 0.987164f, 0.091630f, 0.905614f, 0.817681f, 0.787834f, 0.912987f, 0.449114f, 0.769925f, 0.535947f, 0.151669f, 0.291871f, 0.956991f,
			0.201614f, 0.458043f, 0.108650f, 0.189198f, 0.343385f, 0.707437f, 0.572032f, 0.112830f, 0.299559f, 0.533619f, 0.560607f, 0.302137f, 0.298810f, 0.700633f, 0.857234f, 0.262832f,
            0.540379f, 0.549890f, 0.930636f, 0.124698f, 0.958061f, 0.742567f, 0.213818f, 0.163282f, 0.840874f, 0.081225f, 0.285288f, 0.494906f, 0.960816f, 0.630047f, 0.251322f, 0.563709f,
			0.130155f, 0.279816f, 0.416583f, 0.162613f, 0.277585f, 0.132892f, 0.094613f, 0.347452f, 0.682836f, 0.235912f, 0.689546f, 0.956886f, 0.426290f, 0.475852f, 0.161817f, 0.605434f,
            0.738695f, 0.620725f, 0.426704f, 0.779536f, 0.797975f, 0.790164f, 0.049613f, 0.380668f, 0.361144f, 0.297045f, 0.802260f, 0.223365f, 0.991100f, 0.575659f, 0.034063f, 0.641882f,
			0.016110f, 0.475862f, 0.389361f, 0.725598f, 0.696762f, 0.897515f, 0.607065f, 0.439244f, 0.678656f, 0.730782f, 0.805985f, 0.493441f, 0.908055f, 0.860485f, 0.754622f, 0.299086f,
            0.363286f, 0.328075f, 0.867295f, 0.136760f, 0.859232f, 0.962385f, 0.375776f, 0.796174f, 0.109023f, 0.913994f, 0.855902f, 0.391903f, 0.490650f, 0.109903f, 0.245911f, 0.898222f,
			0.692793f, 0.207801f, 0.793388f, 0.836437f, 0.501555f, 0.442264f, 0.273983f, 0.724212f, 0.756440f, 0.204413f, 0.777815f, 0.960948f, 0.812614f, 0.966499f, 0.314796f, 0.282756f,
            0.201821f, 0.665815f, 0.352419f, 0.360354f, 0.449771f, 0.696713f, 0.404667f, 0.308045f, 0.429777f, 0.818125f, 0.319823f, 0.977753f, 0.345346f, 0.614736f, 0.888562f, 0.531799f,
			0.313051f, 0.553149f, 0.438120f, 0.788833f, 0.821429f, 0.021888f, 0.567978f, 0.221354f, 0.553783f, 0.020073f, 0.753345f, 0.066818f, 0.561847f, 0.958364f, 0.920310f, 0.821175f,
            0.088385f, 0.911949f, 0.721883f, 0.550158f, 0.319319f, 0.617199f, 0.766396f, 0.141219f, 0.997406f, 0.741770f, 0.576599f, 0.024426f, 0.698149f, 0.913561f, 0.538404f, 0.229324f,
			0.639786f, 0.534876f, 0.228422f, 0.000574f, 0.075735f, 0.360824f, 0.784275f, 0.327293f, 0.772189f, 0.190756f, 0.429229f, 0.473776f, 0.535620f, 0.660625f, 0.429841f, 0.561759f,
            0.855929f, 0.395261f, 0.572773f, 0.737716f, 0.357422f, 0.189283f, 0.529549f, 0.899744f, 0.686109f, 0.161902f, 0.150447f, 0.491739f, 0.949252f, 0.500235f, 0.189134f, 0.313296f,
			0.223799f, 0.263966f, 0.553239f, 0.196172f, 0.523264f, 0.042046f, 0.272463f, 0.998110f, 0.147883f, 0.618976f, 0.691869f, 0.189872f, 0.885969f, 0.716284f, 0.625829f, 0.640097f,
            0.692105f, 0.666706f, 0.474201f, 0.217674f, 0.765986f, 0.234480f, 0.448885f, 0.266543f, 0.993896f, 0.760791f, 0.637959f, 0.609803f, 0.653663f, 0.761750f, 0.896188f, 0.926250f,
			0.544878f, 0.245914f, 0.176700f, 0.490558f, 0.866382f, 0.656788f, 0.754365f, 0.734854f, 0.589951f, 0.513053f, 0.121276f, 0.112966f, 0.739441f, 0.725855f, 0.856361f, 0.977866f,
            0.740804f, 0.805505f, 0.639490f, 0.166771f, 0.732479f, 0.895570f, 0.742381f, 0.443175f, 0.803316f, 0.696037f, 0.048430f, 0.810270f, 0.312095f, 0.943503f, 0.261946f, 0.608701f,
			0.462088f, 0.989867f, 0.291183f, 0.930356f, 0.289756f, 0.191623f, 0.105177f, 0.578865f, 0.045527f, 0.769152f, 0.874357f, 0.943202f, 0.145741f, 0.838978f, 0.078688f, 0.451393f,
            0.316871f, 0.743577f, 0.627317f, 0.578569f, 0.093500f, 0.595579f, 0.641802f, 0.124810f, 0.963929f, 0.234948f, 0.073434f, 0.678338f, 0.655245f, 0.234906f, 0.141788f, 0.264730f,
			0.730509f, 0.601433f, 0.304624f, 0.562342f, 0.993801f, 0.613802f, 0.937836f, 0.138432f, 0.709113f, 0.927994f, 0.598133f, 0.945817f, 0.170348f, 0.562751f, 0.590460f, 0.412806f,
            0.500786f, 0.991589f, 0.934649f, 0.273904f, 0.232765f, 0.173627f, 0.931145f, 0.559523f, 0.458190f, 0.613972f, 0.728942f, 0.048812f, 0.769435f, 0.387935f, 0.774973f, 0.013920f,
			0.958878f, 0.720884f, 0.196102f, 0.164162f, 0.376299f, 0.938367f, 0.654315f, 0.166964f, 0.463967f, 0.783851f, 0.084766f, 0.658451f, 0.235361f, 0.609461f, 0.594330f, 0.628212f,
            0.718797f, 0.424265f, 0.019535f, 0.772259f, 0.481056f, 0.261102f, 0.302635f, 0.919713f, 0.192276f, 0.546952f, 0.189027f, 0.482185f, 0.356738f, 0.917890f, 0.200953f, 0.430285f,
			0.183473f, 0.406824f, 0.230043f, 0.869523f, 0.009643f, 0.470741f, 0.445113f, 0.637351f, 0.132256f, 0.606100f, 0.723261f, 0.559166f, 0.937340f, 0.865542f, 0.645344f, 0.019263f,
            0.850574f, 0.204458f, 0.895768f, 0.469703f, 0.773773f, 0.016266f, 0.981349f, 0.063004f, 0.038396f, 0.485687f, 0.121737f, 0.656076f, 0.140912f, 0.542099f, 0.388021f, 0.754702f,
			0.501008f, 0.419795f, 0.992794f, 0.569702f, 0.126385f, 0.847547f, 0.716237f, 0.611087f, 0.291492f, 0.646219f, 0.162199f, 0.054491f, 0.394944f, 0.849543f, 0.727663f, 0.064657f,
            0.459071f, 0.597475f, 0.714157f, 0.420322f, 0.526871f, 0.946681f, 0.688802f, 0.558421f, 0.395704f, 0.808235f, 0.473320f, 0.517520f, 0.737539f, 0.538205f, 0.089613f, 0.662200f,
			0.185153f, 0.817549f, 0.125551f, 0.897593f, 0.228318f, 0.920888f, 0.544394f, 0.501680f, 0.814827f, 0.466345f, 0.527414f, 0.146873f, 0.359364f, 0.119719f, 0.258440f, 0.883457f,
            0.319933f, 0.928852f, 0.161313f, 0.717347f, 0.905691f, 0.835957f, 0.190483f, 0.456408f, 0.014559f, 0.418268f, 0.094371f, 0.942875f, 0.608512f, 0.645362f, 0.642014f, 0.606046f,
			0.470646f, 0.207487f, 0.184785f, 0.694316f, 0.110922f, 0.596717f, 0.873931f, 0.079118f, 0.004797f, 0.341692f, 0.215983f, 0.871720f, 0.994579f, 0.312753f, 0.695872f, 0.960239f,
            0.136772f, 0.526617f, 0.324827f, 0.901484f, 0.723923f, 0.987890f, 0.162538f, 0.552596f, 0.559519f, 0.221703f, 0.545969f, 0.878732f, 0.110644f, 0.412059f, 0.602484f, 0.760632f,
			0.143097f, 0.848408f, 0.133743f, 0.176404f, 0.433838f, 0.356389f, 0.554633f, 0.306999f, 0.589048f, 0.231045f, 0.673169f, 0.777586f, 0.449071f, 0.355308f, 0.228278f, 0.933172f,
            0.420981f, 0.895869f, 0.862517f, 0.118719f, 0.744067f, 0.852169f, 0.261421f, 0.923401f, 0.351930f, 0.560640f, 0.426716f, 0.133275f, 0.896841f, 0.253229f, 0.672233f, 0.098920f,
			0.518726f, 0.366090f, 0.680133f, 0.957125f, 0.743277f, 0.110979f, 0.722134f, 0.836798f, 0.994889f, 0.493074f, 0.653240f, 0.478862f, 0.010134f, 0.848059f, 0.624650f, 0.489341f,
            0.569989f, 0.985920f, 0.814092f, 0.803689f, 0.539121f, 0.279808f, 0.979132f, 0.376335f, 0.493443f, 0.811588f, 0.932521f, 0.418866f, 0.075749f, 0.465899f, 0.596064f, 0.288613f,
			0.479356f, 0.317743f, 0.582443f, 0.940873f, 0.273572f, 0.427752f, 0.912510f, 0.592029f, 0.046347f, 0.916995f, 0.703584f, 0.965346f, 0.274267f, 0.596967f, 0.171989f, 0.932457f,
            0.406249f, 0.338518f, 0.421333f, 0.861258f, 0.448351f, 0.290133f, 0.191276f, 0.540292f, 0.952156f, 0.465114f, 0.437447f, 0.964754f, 0.389444f, 0.617480f, 0.565949f, 0.745922f,
			0.215003f, 0.798200f, 0.415264f, 0.460189f, 0.807265f, 0.507772f, 0.107751f, 0.741359f, 0.880618f, 0.803514f, 0.333899f, 0.557228f, 0.475916f, 0.835802f, 0.256334f, 0.904589f,
            0.580973f, 0.976768f, 0.620767f, 0.439441f, 0.479976f, 0.415393f, 0.623680f, 0.895957f, 0.915340f, 0.976582f, 0.214940f, 0.823858f, 0.135682f, 0.199343f, 0.477328f, 0.820162f,
			0.855608f, 0.920796f, 0.042596f, 0.685763f, 0.836430f, 0.873381f, 0.465266f, 0.702607f, 0.496781f, 0.327189f, 0.894543f, 0.493475f, 0.718946f, 0.204872f, 0.325534f, 0.259868f,
            0.098154f, 0.158777f, 0.248285f, 0.263217f, 0.624750f, 0.153260f, 0.171832f, 0.529960f, 0.574618f, 0.591273f, 0.358302f, 0.146503f, 0.146980f, 0.896355f, 0.429926f, 0.705426f,
			0.819613f, 0.058496f, 0.769004f, 0.934449f, 0.047865f, 0.937179f, 0.729013f, 0.303100f, 0.350444f, 0.627999f, 0.844327f, 0.461561f, 0.410363f, 0.077172f, 0.380747f, 0.372290f,
            0.311161f, 0.099751f, 0.673085f, 0.005383f, 0.830135f, 0.697567f, 0.111677f, 0.912053f, 0.299470f, 0.739002f, 0.120426f, 0.172786f, 0.796490f, 0.271028f, 0.414540f, 0.194428f,
			0.322516f, 0.010479f, 0.940411f, 0.462602f, 0.066358f, 0.356060f, 0.453836f, 0.100109f, 0.306669f, 0.491988f, 0.403775f, 0.373461f, 0.900378f, 0.376071f, 0.953343f, 0.476414f,
            0.284104f, 0.282902f, 0.259410f, 0.285826f, 0.266219f, 0.434016f, 0.226571f, 0.477633f, 0.428028f, 0.479378f, 0.761036f, 0.273846f, 0.501374f, 0.842157f, 0.337816f, 0.890679f,
			0.805007f, 0.587070f, 0.604796f, 0.131438f, 0.333822f, 0.411484f, 0.899862f, 0.696973f, 0.385146f, 0.155901f, 0.813331f, 0.578950f, 0.916157f, 0.297563f, 0.695218f, 0.318427f,
            0.750932f, 0.943070f, 0.998564f, 0.218770f, 0.072778f, 0.620683f, 0.630989f, 0.603873f, 0.059364f, 0.119546f, 0.842339f, 0.611117f, 0.326811f, 0.006571f, 0.538724f, 0.089111f,
			0.557459f, 0.853892f, 0.242570f, 0.231557f, 0.566785f, 0.436132f, 0.212052f, 0.575910f, 0.573632f, 0.223426f, 0.237695f, 0.549567f, 0.308579f, 0.669835f, 0.509349f, 0.638573f,
            0.984170f, 0.835078f, 0.865912f, 0.241633f, 0.307815f, 0.764295f, 0.116434f, 0.164133f, 0.770253f, 0.305897f, 0.398791f, 0.915491f, 0.924625f, 0.185762f, 0.983308f, 0.329755f,
			0.165246f, 0.719364f, 0.553888f, 0.380573f, 0.407837f, 0.899365f, 0.202233f, 0.248231f, 0.037430f, 0.693421f, 0.557603f, 0.488355f, 0.887256f, 0.875926f, 0.403243f, 0.415350f,
            0.105401f, 0.655474f, 0.026566f, 0.439266f, 0.911533f, 0.719139f, 0.498864f, 0.285521f, 0.756021f, 0.846129f, 0.928727f, 0.782109f, 0.324880f, 0.950163f, 0.432184f, 0.808160f,
			0.828481f, 0.240161f, 0.588260f, 0.977954f, 0.742374f, 0.393850f, 0.037607f, 0.988713f, 0.995488f, 0.410678f, 0.456706f, 0.232694f, 0.496564f, 0.050204f, 0.680238f, 0.387508f,
            0.599307f, 0.846198f, 0.638206f, 0.999185f, 0.334352f, 0.252433f, 0.395126f, 0.913137f, 0.049168f, 0.792879f, 0.449318f, 0.255742f, 0.937635f, 0.223333f, 0.942277f, 0.261775f,
			0.881287f, 0.585729f, 0.295395f, 0.858012f, 0.992763f, 0.580287f, 0.529116f, 0.970863f, 0.442945f, 0.334570f, 0.736466f, 0.756358f, 0.701351f, 0.135065f, 0.076590f, 0.988877f,
            0.821953f, 0.919717f, 0.605505f, 0.340596f, 0.789394f, 0.982985f, 0.182746f, 0.812165f, 0.776130f, 0.219152f, 0.530292f, 0.393275f, 0.466884f, 0.523931f, 0.101787f, 0.923910f,
			0.531882f, 0.195951f, 0.432513f, 0.317969f, 0.899230f, 0.959169f, 0.088257f, 0.517069f, 0.246088f, 0.113432f, 0.932421f, 0.410578f, 0.023902f, 0.298967f, 0.101524f, 0.567569f,
            0.916157f, 0.752929f, 0.583655f, 0.007166f, 0.644638f, 0.330446f, 0.013768f, 0.554174f, 0.387064f, 0.349120f, 0.987015f, 0.824911f, 0.463799f, 0.328236f, 0.228744f, 0.630223f,
			0.775374f, 0.261188f, 0.586664f, 0.628876f, 0.885839f, 0.467935f, 0.001671f, 0.490076f, 0.779897f, 0.196803f, 0.081150f, 0.406546f, 0.261682f, 0.231374f, 0.454190f, 0.727030f,
            0.370545f, 0.046750f, 0.483845f, 0.160213f, 0.115274f, 0.543546f, 0.799146f, 0.155520f, 0.168631f, 0.593044f, 0.535511f, 0.445088f, 0.225442f, 0.281838f, 0.214438f, 0.355134f,
			0.577803f, 0.520731f, 0.411877f, 0.692694f, 0.010741f, 0.530602f, 0.942900f, 0.421161f, 0.088442f, 0.638912f, 0.797740f, 0.697250f, 0.861977f, 0.852059f, 0.508207f, 0.842301f,
            0.511797f, 0.744589f, 0.682626f, 0.004542f, 0.310682f, 0.882969f, 0.414955f, 0.157318f, 0.861478f, 0.077667f, 0.575683f, 0.385511f, 0.554460f, 0.030360f, 0.148430f, 0.096852f,
			0.905607f, 0.712322f, 0.940074f, 0.543212f, 0.711064f, 0.599593f, 0.752573f, 0.120951f, 0.754660f, 0.611835f, 0.330889f, 0.832905f, 0.132196f, 0.954476f, 0.223229f, 0.163155f,
            0.678759f, 0.622577f, 0.570115f, 0.370930f, 0.846313f, 0.958154f, 0.487903f, 0.679160f, 0.939023f, 0.150108f, 0.048921f, 0.668093f, 0.654592f, 0.723882f, 0.499279f, 0.221077f,
			0.199292f, 0.713186f, 0.034832f, 0.539274f, 0.116376f, 0.377936f, 0.838998f, 0.366266f, 0.013680f, 0.177019f, 0.884934f, 0.994283f, 0.856735f, 0.635153f, 0.401854f, 0.797358f,
            0.355755f, 0.485780f, 0.932581f, 0.264017f, 0.201828f, 0.848148f, 0.892544f, 0.540507f, 0.912208f, 0.222719f, 0.258482f, 0.794080f, 0.065642f, 0.988557f, 0.219061f, 0.624594f,
			0.106088f, 0.753591f, 0.416804f, 0.960782f, 0.246652f, 0.683924f, 0.002097f, 0.911614f, 0.524383f, 0.801068f, 0.827340f, 0.074203f, 0.434632f, 0.967471f, 0.966142f, 0.156266f,
            0.043709f, 0.751466f, 0.201663f, 0.930579f, 0.232369f, 0.805168f, 0.245330f, 0.524264f, 0.892820f, 0.832664f, 0.164933f, 0.040893f, 0.247415f, 0.274446f, 0.234693f, 0.307384f,
			0.136368f, 0.354890f, 0.749632f, 0.826214f, 0.788274f, 0.557840f, 0.049222f, 0.669936f, 0.567787f, 0.552373f, 0.472005f, 0.581675f, 0.439841f, 0.373787f, 0.685357f, 0.005233f,
            0.307612f, 0.678555f, 0.114648f, 0.715483f, 0.406653f, 0.176785f, 0.756754f, 0.002939f, 0.576102f, 0.510756f, 0.686677f, 0.671747f, 0.456088f, 0.423491f, 0.315784f, 0.824684f,
			0.966542f, 0.352780f, 0.484701f, 0.993586f, 0.982517f, 0.082847f, 0.333566f, 0.493804f, 0.171064f, 0.184626f, 0.542785f, 0.704596f, 0.251987f, 0.462502f, 0.382409f, 0.171854f,
            0.468987f, 0.633221f, 0.031204f, 0.369964f, 0.335244f, 0.815066f, 0.332815f, 0.277049f, 0.214008f, 0.529576f, 0.205785f, 0.092890f, 0.332736f, 0.448346f, 0.541605f, 0.561957f,
			0.615907f, 0.281304f, 0.211222f, 0.977813f, 0.772368f, 0.197320f, 0.601030f, 0.634024f, 0.365701f, 0.524694f, 0.547058f, 0.503831f, 0.530463f, 0.002877f, 0.049571f, 0.021474f,
            0.368005f, 0.111379f, 0.465701f, 0.373678f, 0.940959f, 0.029765f, 0.584339f, 0.908519f, 0.804054f, 0.812224f, 0.059865f, 0.485530f, 0.477289f, 0.385421f, 0.103387f, 0.239093f,
			0.167409f, 0.388262f, 0.103660f, 0.000114f, 0.048219f, 0.197729f, 0.605880f, 0.381549f, 0.189445f, 0.361900f, 0.935119f, 0.578281f, 0.606638f, 0.353767f, 0.395427f, 0.205229f,
            0.500292f, 0.598258f, 0.483513f, 0.716490f, 0.661746f, 0.217913f, 0.839917f, 0.024732f, 0.523860f, 0.906141f, 0.835574f, 0.218085f, 0.567518f, 0.024510f, 0.988591f, 0.313786f,
			0.714521f, 0.548605f, 0.759551f, 0.609800f, 0.565885f, 0.916072f, 0.626366f, 0.704910f, 0.424033f, 0.800924f, 0.689747f, 0.015704f, 0.156789f, 0.970284f, 0.904448f, 0.535410f,
            0.618838f, 0.508312f, 0.325922f, 0.445216f, 0.083279f, 0.191400f, 0.032272f, 0.583698f, 0.272047f, 0.041614f, 0.682610f, 0.908735f, 0.419833f, 0.354616f, 0.660083f, 0.670012f,
			0.334461f, 0.205757f, 0.085736f, 0.660294f, 0.400520f, 0.929883f, 0.067559f, 0.361170f, 0.378798f, 0.242262f, 0.903673f, 0.527278f, 0.918559f, 0.233425f, 0.690225f, 0.111809f,
            0.952840f, 0.401740f, 0.157884f, 0.202383f, 0.115496f, 0.303892f, 0.668359f, 0.674909f, 0.688240f, 0.047159f, 0.770369f, 0.007465f, 0.934418f, 0.589559f, 0.462308f, 0.007394f,
			0.909411f, 0.524707f, 0.585877f, 0.503781f, 0.846387f, 0.630285f, 0.455500f, 0.681761f, 0.603459f, 0.800667f, 0.317710f, 0.911021f, 0.733080f, 0.269005f, 0.511252f, 0.793102f,
            0.151470f, 0.224306f, 0.003934f, 0.812693f, 0.877731f, 0.947073f, 0.160509f, 0.372051f, 0.810113f, 0.836802f, 0.902943f, 0.217167f, 0.556084f, 0.432270f, 0.911972f, 0.177004f,
			0.044343f, 0.047921f, 0.684500f, 0.436020f, 0.282889f, 0.775294f, 0.454425f, 0.187185f, 0.805013f, 0.172299f, 0.854364f, 0.027615f, 0.431385f, 0.786170f, 0.139471f, 0.345790f,
            0.696513f, 0.746807f, 0.206278f, 0.964428f, 0.532503f, 0.754228f, 0.496961f, 0.251965f, 0.999311f, 0.869451f, 0.707122f, 0.309857f, 0.093550f, 0.936002f, 0.724645f, 0.770712f,
			0.464140f, 0.760689f, 0.774838f, 0.187460f, 0.896500f, 0.355532f, 0.897887f, 0.042893f, 0.020613f, 0.621345f, 0.003183f, 0.562121f, 0.888937f, 0.664515f, 0.573617f, 0.254445f,
            0.867649f, 0.546239f, 0.305669f, 0.499521f, 0.352026f, 0.240158f, 0.116787f, 0.402515f, 0.728657f, 0.264564f, 0.767208f, 0.374689f, 0.993704f, 0.327532f, 0.429133f, 0.101035f,
			0.016053f, 0.279887f, 0.713336f, 0.653675f, 0.522390f, 0.579256f, 0.525505f, 0.349225f, 0.211543f, 0.670851f, 0.994410f, 0.429991f, 0.944335f, 0.028248f, 0.868331f, 0.164546f,
            0.908215f, 0.651666f, 0.357339f, 0.302535f, 0.334093f, 0.661901f, 0.816697f, 0.360167f, 0.156582f, 0.259022f, 0.073315f, 0.976957f, 0.302519f, 0.135374f, 0.774588f, 0.974519f,
			0.798693f, 0.707728f, 0.102112f, 0.664978f, 0.100014f, 0.530609f, 0.589275f, 0.708739f, 0.732154f, 0.518004f, 0.019884f, 0.003517f, 0.905275f, 0.854800f, 0.319834f, 0.521517f,
            0.948671f, 0.538230f, 0.702595f, 0.315933f, 0.903485f, 0.891281f, 0.415612f, 0.062139f, 0.550871f, 0.671312f, 0.158950f, 0.952773f, 0.025603f, 0.733518f, 0.096014f, 0.155889f,
			0.657341f, 0.464977f, 0.732907f, 0.270813f, 0.618329f, 0.767597f, 0.644625f, 0.097203f, 0.776177f, 0.312430f, 0.250948f, 0.523427f, 0.749987f, 0.416307f, 0.348913f, 0.174883f,
            0.689103f, 0.895571f, 0.368298f, 0.220185f, 0.644013f, 0.999277f, 0.934948f, 0.511840f, 0.011400f, 0.316610f, 0.127321f, 0.324162f, 0.462187f, 0.218027f, 0.252997f, 0.014236f,
			0.034303f, 0.407723f, 0.595502f, 0.573174f, 0.863763f, 0.388254f, 0.381401f, 0.831700f, 0.109474f, 0.999033f, 0.299090f, 0.070875f, 0.404025f, 0.769747f, 0.953053f, 0.337070f,
            0.996800f, 0.654645f, 0.615563f, 0.387545f, 0.996169f, 0.098382f, 0.243250f, 0.696655f, 0.450467f, 0.545415f, 0.301941f, 0.280381f, 0.895913f, 0.143442f, 0.265884f, 0.912101f,
			0.869788f, 0.023351f, 0.080603f, 0.097790f, 0.651600f, 0.586052f, 0.839310f, 0.933324f, 0.805040f, 0.754689f, 0.946504f, 0.391508f, 0.092798f, 0.890388f, 0.528784f, 0.992274f,
            0.557973f, 0.154180f, 0.294522f, 0.849238f, 0.725572f, 0.449445f, 0.690173f, 0.921853f, 0.266363f, 0.494307f, 0.873146f, 0.188281f, 0.485043f, 0.128141f, 0.754645f, 0.475272f,
			0.455922f, 0.533494f, 0.225586f, 0.907761f, 0.746237f, 0.941127f, 0.684823f, 0.883861f, 0.085815f, 0.133523f, 0.029190f, 0.489845f, 0.946848f, 0.345726f, 0.527938f, 0.602657f,
            0.348176f, 0.831391f, 0.804152f, 0.518477f, 0.888902f, 0.185867f, 0.280627f, 0.520205f, 0.766628f, 0.088484f, 0.048962f, 0.109819f, 0.301013f, 0.112998f, 0.429369f, 0.291021f,
			0.348427f, 0.539797f, 0.958411f, 0.445745f, 0.939843f, 0.562084f, 0.016899f, 0.757092f, 0.824496f, 0.096806f, 0.778782f, 0.979989f, 0.295790f, 0.036589f, 0.727595f, 0.860422f,
            0.161873f, 0.847166f, 0.887142f, 0.742502f, 0.203190f, 0.090445f, 0.146989f, 0.481836f, 0.828490f, 0.310665f, 0.191220f, 0.330496f, 0.731661f, 0.788974f, 0.239879f, 0.252898f,
			0.489531f, 0.924007f, 0.949828f, 0.688446f, 0.893540f, 0.295337f, 0.694445f, 0.109920f, 0.189948f, 0.075424f, 0.651406f, 0.057441f, 0.572296f, 0.423015f, 0.752545f, 0.154501f,
            0.141282f, 0.183090f, 0.752169f, 0.648484f, 0.125763f, 0.253071f, 0.555019f, 0.235172f, 0.686895f, 0.944181f, 0.009399f, 0.993865f, 0.936208f, 0.026191f, 0.062246f, 0.573176f,
			0.296832f, 0.058477f, 0.213122f, 0.884476f, 0.806741f, 0.710474f, 0.615911f, 0.122187f, 0.626578f, 0.759726f, 0.734930f, 0.372884f, 0.314065f, 0.671858f, 0.093880f, 0.209725f,
            0.282262f, 0.081670f, 0.874794f, 0.301428f, 0.475862f, 0.281087f, 0.706727f, 0.157212f, 0.104696f, 0.252561f, 0.321481f, 0.555237f, 0.909704f, 0.120793f, 0.315512f, 0.163084f,
			0.127502f, 0.941760f, 0.801529f, 0.245596f, 0.303637f, 0.092178f, 0.403767f, 0.154867f, 0.227694f, 0.410078f, 0.912641f, 0.525179f, 0.313926f, 0.580584f, 0.370711f, 0.712438f,
            0.593425f, 0.875817f, 0.864538f, 0.787639f, 0.096351f, 0.227234f, 0.655099f, 0.442666f, 0.549580f, 0.164335f, 0.650124f, 0.235425f, 0.285302f, 0.529855f, 0.955180f, 0.639479f,
			0.050978f, 0.372256f, 0.747666f, 0.485716f, 0.500354f, 0.807764f, 0.747095f, 0.705398f, 0.371973f, 0.048861f, 0.145696f, 0.008936f, 0.126334f, 0.271463f, 0.813145f, 0.877748f,
            0.941550f, 0.962466f, 0.648030f, 0.616258f, 0.365919f, 0.037004f, 0.970048f, 0.428801f, 0.180691f, 0.649064f, 0.336322f, 0.356920f, 0.523740f, 0.732351f, 0.778427f, 0.897402f,
			0.082186f, 0.890037f, 0.729726f, 0.038347f, 0.163521f, 0.950760f, 0.946651f, 0.548275f, 0.003517f, 0.978833f, 0.813212f, 0.980175f, 0.353375f, 0.115058f, 0.367189f, 0.711349f,
            0.559266f, 0.707247f, 0.803979f, 0.830496f, 0.316869f, 0.114284f, 0.936372f, 0.568145f, 0.615433f, 0.391304f, 0.895906f, 0.881689f, 0.989623f, 0.514664f, 0.453839f, 0.231926f,
			0.942255f, 0.250965f, 0.343862f, 0.602090f, 0.800272f, 0.937401f, 0.962169f, 0.802512f, 0.777999f, 0.505617f, 0.154536f, 0.337275f, 0.209780f, 0.286263f, 0.257710f, 0.676523f,
            0.905717f, 0.709268f, 0.494937f, 0.857134f, 0.186806f, 0.052648f, 0.577372f, 0.610206f, 0.369482f, 0.641445f, 0.755588f, 0.262810f, 0.495467f, 0.541692f, 0.292924f, 0.278645f,
			0.024225f, 0.736284f, 0.437112f, 0.612503f, 0.864058f, 0.235890f, 0.046797f, 0.523737f, 0.501283f, 0.555321f, 0.112661f, 0.970041f, 0.902574f, 0.302799f, 0.497870f, 0.960874f,
            0.962809f, 0.025754f, 0.265602f, 0.916874f, 0.793021f, 0.078963f, 0.301902f, 0.549331f, 0.326868f, 0.419440f, 0.931529f, 0.808191f, 0.235519f, 0.914833f, 0.408045f, 0.569725f,
			0.558466f, 0.846578f, 0.227876f, 0.658390f, 0.144765f, 0.543305f, 0.945075f, 0.394804f, 0.476090f, 0.196509f, 0.502454f, 0.654819f, 0.401977f, 0.205939f, 0.361731f, 0.176901f,
            0.333771f, 0.836963f, 0.086564f, 0.883413f, 0.838149f, 0.637547f, 0.390905f, 0.559410f, 0.289008f, 0.663764f, 0.926731f, 0.765008f, 0.520241f, 0.770315f, 0.660298f, 0.667649f,
			0.922561f, 0.597249f, 0.192393f, 0.583633f, 0.119712f, 0.500704f, 0.460960f, 0.486966f, 0.659508f, 0.208631f, 0.249314f, 0.171036f, 0.705531f, 0.266777f, 0.687168f, 0.612114f,
            0.962350f, 0.502317f, 0.707088f, 0.234704f, 0.848222f, 0.391640f, 0.759571f, 0.165638f, 0.642648f, 0.357505f, 0.946390f, 0.610746f, 0.772275f, 0.548077f, 0.043468f, 0.949288f,
			0.815138f, 0.817701f, 0.740238f, 0.971516f, 0.465220f, 0.208924f, 0.479100f, 0.859023f, 0.331794f, 0.921983f, 0.270717f, 0.507372f, 0.911466f, 0.928137f, 0.935219f, 0.024950f,
            0.731867f, 0.251316f, 0.630099f, 0.287073f, 0.771200f, 0.906851f, 0.064188f, 0.214667f, 0.808795f, 0.992395f, 0.451754f, 0.228186f, 0.273440f, 0.353499f, 0.473258f, 0.428630f,
			0.033729f, 0.676560f, 0.087302f, 0.923259f, 0.092894f, 0.995056f, 0.500564f, 0.399398f, 0.972272f, 0.459159f, 0.680624f, 0.508949f, 0.211956f, 0.125250f, 0.857138f, 0.399225f,
            0.341751f, 0.187864f, 0.684498f, 0.710166f, 0.084178f, 0.856584f, 0.330318f, 0.339303f, 0.040552f, 0.083557f, 0.137602f, 0.872978f, 0.618950f, 0.036609f, 0.708058f, 0.402581f,
			0.205324f, 0.281362f, 0.192961f, 0.014820f, 0.769966f, 0.735305f, 0.637875f, 0.867915f, 0.869535f, 0.328310f, 0.302204f, 0.528069f, 0.244660f, 0.987057f, 0.477652f, 0.834386f,
            0.550058f, 0.126327f, 0.334653f, 0.231860f, 0.434521f, 0.075158f, 0.093737f, 0.749265f, 0.898682f, 0.940638f, 0.300966f, 0.271583f, 0.846690f, 0.001935f, 0.277732f, 0.436304f,
			0.776421f, 0.926063f, 0.343968f, 0.253866f, 0.649470f, 0.973299f, 0.541479f, 0.039740f, 0.058917f, 0.553833f, 0.792294f, 0.302804f, 0.802850f, 0.920126f, 0.278132f, 0.140074f,
            0.593687f, 0.020039f, 0.807146f, 0.392844f, 0.839837f, 0.723457f, 0.461881f, 0.363321f, 0.764416f, 0.834267f, 0.539788f, 0.622771f, 0.683673f, 0.439644f, 0.047606f, 0.826159f,
			0.344533f, 0.564557f, 0.736962f, 0.569703f, 0.990862f, 0.942847f, 0.696052f, 0.609554f, 0.198030f, 0.246046f, 0.220046f, 0.228621f, 0.297194f, 0.070802f, 0.529770f, 0.149929f,
            0.341938f, 0.191600f, 0.245426f, 0.252753f, 0.114864f, 0.634720f, 0.815265f, 0.806456f, 0.936602f, 0.984388f, 0.984008f, 0.993860f, 0.638596f, 0.537949f, 0.059666f, 0.934545f,
			0.043838f, 0.193250f, 0.376865f, 0.576959f, 0.366403f, 0.233473f, 0.540041f, 0.329253f, 0.861973f, 0.650880f, 0.564595f, 0.638054f, 0.447088f, 0.942967f, 0.518814f, 0.829373f,
            0.064984f, 0.621619f, 0.129744f, 0.750823f, 0.421205f, 0.816374f, 0.453799f, 0.408396f, 0.156211f, 0.901263f, 0.003056f, 0.149893f, 0.750182f, 0.633353f, 0.021145f, 0.602591f,
			0.752085f, 0.385518f, 0.373927f, 0.003502f, 0.109715f, 0.509047f, 0.128532f, 0.516430f, 0.837958f, 0.402122f, 0.793502f, 0.845906f, 0.322630f, 0.482674f, 0.518537f, 0.163750f,
            0.203517f, 0.815795f, 0.614114f, 0.261586f, 0.532065f, 0.667488f, 0.870466f, 0.837781f, 0.276226f, 0.634266f, 0.813883f, 0.261993f, 0.731073f, 0.497233f, 0.027479f, 0.931135f,
			0.381940f, 0.462354f, 0.225242f, 0.713262f, 0.593692f, 0.591875f, 0.784701f, 0.790778f, 0.328485f, 0.386164f, 0.971274f, 0.555561f, 0.737582f, 0.673271f, 0.579415f, 0.119510f,
            0.358286f, 0.572606f, 0.813175f, 0.047914f, 0.716137f, 0.501525f, 0.058600f, 0.225555f, 0.240759f, 0.007750f, 0.668356f, 0.320140f, 0.342933f, 0.979886f, 0.898964f, 0.995495f,
			0.709939f, 0.768482f, 0.037518f, 0.406672f, 0.086731f, 0.044700f, 0.117240f, 0.198780f, 0.014111f, 0.188062f, 0.147571f, 0.365040f, 0.862395f, 0.901065f, 0.766101f, 0.270812f,
            0.011556f, 0.029467f, 0.288008f, 0.375681f, 0.069840f, 0.699102f, 0.173022f, 0.519249f, 0.274132f, 0.378163f, 0.006843f, 0.695346f, 0.427597f, 0.343684f, 0.094157f, 0.000213f,
			0.502942f, 0.879600f, 0.192073f, 0.238737f, 0.437724f, 0.730457f, 0.265212f, 0.485049f, 0.581208f, 0.705192f, 0.126230f, 0.225008f, 0.830697f, 0.108942f, 0.352028f, 0.831478f,
            0.630680f, 0.272009f, 0.511361f, 0.008255f, 0.486975f, 0.360113f, 0.211540f, 0.115034f, 0.090622f, 0.398361f, 0.502185f, 0.282754f, 0.092426f, 0.723974f, 0.608313f, 0.255417f,
			0.585920f, 0.870403f, 0.361456f, 0.871296f, 0.468289f, 0.500575f, 0.311400f, 0.202777f, 0.155190f, 0.889460f, 0.204372f, 0.547024f, 0.943731f, 0.802283f, 0.090099f, 0.326765f,
            0.702241f, 0.149503f, 0.176245f, 0.533044f, 0.322953f, 0.741188f, 0.120817f, 0.005404f, 0.877505f, 0.758450f, 0.557301f, 0.283896f, 0.304056f, 0.106572f, 0.157079f, 0.822837f,
			0.855185f, 0.023719f, 0.097561f, 0.429323f, 0.678002f, 0.313318f, 0.208544f, 0.539308f, 0.582640f, 0.140013f, 0.442533f, 0.006391f, 0.806494f, 0.099903f, 0.343806f, 0.677518f,
            0.928645f, 0.154499f, 0.478735f, 0.120070f, 0.521299f, 0.916501f, 0.195672f, 0.659027f, 0.623152f, 0.100548f, 0.617537f, 0.884737f, 0.436001f, 0.219878f, 0.773074f, 0.142898f,
			0.947992f, 0.036367f, 0.837582f, 0.907945f, 0.980091f, 0.742163f, 0.735772f, 0.228684f, 0.483067f, 0.633681f, 0.278898f, 0.278513f, 0.955628f, 0.625673f, 0.179684f, 0.638249f,
            0.253669f, 0.675357f, 0.652977f, 0.618491f, 0.665675f, 0.318526f, 0.657542f, 0.325665f, 0.560921f, 0.166557f, 0.891854f, 0.450622f, 0.090322f, 0.507485f, 0.268272f, 0.641118f,
			0.312018f, 0.023459f, 0.706861f, 0.841006f, 0.830786f, 0.050469f, 0.346224f, 0.417818f, 0.341490f, 0.936115f, 0.058080f, 0.320423f, 0.013636f, 0.990662f, 0.693564f, 0.470902f,
            0.085107f, 0.581682f, 0.476929f, 0.725809f, 0.796961f, 0.243727f, 0.256038f, 0.399578f, 0.955883f, 0.477739f, 0.209286f, 0.116191f, 0.867228f, 0.595706f, 0.093380f, 0.402850f,
			0.662976f, 0.987829f, 0.886454f, 0.139231f, 0.054421f, 0.036017f, 0.356252f, 0.777878f, 0.342551f, 0.014429f, 0.045323f, 0.972885f, 0.837608f, 0.322591f, 0.504360f, 0.473576f,
            0.355545f, 0.502514f, 0.288523f, 0.335709f, 0.916929f, 0.764961f, 0.355654f, 0.780218f, 0.130169f, 0.857086f, 0.002813f, 0.461806f, 0.439231f, 0.553104f, 0.180024f, 0.511372f,
			0.166102f, 0.428016f, 0.229941f, 0.948167f, 0.976576f, 0.332357f, 0.200817f, 0.116735f, 0.494322f, 0.741113f, 0.429366f, 0.838120f, 0.604259f, 0.215288f, 0.059709f, 0.046317f,
            0.150495f, 0.762179f, 0.902282f, 0.685121f, 0.497243f, 0.585235f, 0.409540f, 0.181049f, 0.193344f, 0.633361f, 0.443064f, 0.324501f, 0.540525f, 0.233343f, 0.785752f, 0.032939f,
			0.151407f, 0.162703f, 0.829595f, 0.690226f, 0.064497f, 0.796333f, 0.462896f, 0.497970f, 0.301988f, 0.192505f, 0.584944f, 0.286211f, 0.184842f, 0.462389f, 0.985772f, 0.798628f,
            0.914466f, 0.620146f, 0.517927f, 0.916685f, 0.940198f, 0.742935f, 0.656388f, 0.233564f, 0.450210f, 0.979757f, 0.421390f, 0.709064f, 0.358123f, 0.505729f, 0.335112f, 0.559635f,
			0.092023f, 0.265714f, 0.040185f, 0.015890f, 0.126007f, 0.006110f, 0.753810f, 0.244082f, 0.004769f, 0.490835f, 0.089018f, 0.569413f, 0.227339f, 0.934402f, 0.460834f, 0.521934f,
            0.536654f, 0.882489f, 0.319765f, 0.006790f, 0.581177f, 0.424880f, 0.650352f, 0.966685f, 0.215116f, 0.186251f, 0.834234f, 0.390612f, 0.837217f, 0.700494f, 0.917467f, 0.922151f,
			0.204450f, 0.454800f, 0.478100f, 0.534704f, 0.363058f, 0.860587f, 0.949023f, 0.289364f, 0.004494f, 0.179760f, 0.592998f, 0.240168f, 0.654248f, 0.759540f, 0.801863f, 0.707941f,
            0.599927f, 0.502474f, 0.855330f, 0.513896f, 0.160006f, 0.565431f, 0.660689f, 0.148034f, 0.171060f, 0.039446f, 0.560769f, 0.476367f, 0.657147f, 0.724345f, 0.026225f, 0.922540f,
			0.873737f, 0.181805f, 0.729404f, 0.564455f, 0.049190f, 0.125037f, 0.200431f, 0.837437f, 0.605315f, 0.849146f, 0.085422f, 0.543958f, 0.825169f, 0.595628f, 0.579894f, 0.126691f,
            0.493958f, 0.757686f, 0.487482f, 0.757922f, 0.605868f, 0.158248f, 0.309540f, 0.596798f, 0.803224f, 0.820867f, 0.111020f, 0.578124f, 0.451725f, 0.652842f, 0.475185f, 0.055049f,
			0.604279f, 0.057147f, 0.852374f, 0.657826f, 0.032287f, 0.125336f, 0.995285f, 0.768626f, 0.801557f, 0.428066f, 0.682753f, 0.489181f, 0.116717f, 0.750857f, 0.368871f, 0.492398f,
            0.943165f, 0.506438f, 0.331573f, 0.425281f, 0.668019f, 0.567439f, 0.011888f, 0.368115f, 0.590361f, 0.217592f, 0.640634f, 0.785146f, 0.041814f, 0.567710f, 0.467175f, 0.242290f,
			0.527020f, 0.860436f, 0.589741f, 0.793818f, 0.280093f, 0.973971f, 0.889225f, 0.429252f, 0.170749f, 0.114321f, 0.477989f, 0.201508f, 0.409291f, 0.848152f, 0.858684f, 0.554268f,
            0.177876f, 0.335631f, 0.787902f, 0.498155f, 0.592625f, 0.276219f, 0.208872f, 0.087929f, 0.988320f, 0.652100f, 0.718158f, 0.955148f, 0.726526f, 0.510424f, 0.474627f, 0.181768f,
			0.431750f, 0.099482f, 0.075091f, 0.877024f, 0.213872f, 0.811394f, 0.771570f, 0.467441f, 0.384960f, 0.545737f, 0.187058f, 0.480963f, 0.549307f, 0.544133f, 0.123544f, 0.937550f,
            0.836635f, 0.831808f, 0.061393f, 0.040214f, 0.885890f, 0.052475f, 0.833760f, 0.321244f, 0.947086f, 0.389249f, 0.519752f, 0.892390f, 0.519980f, 0.625079f, 0.203724f, 0.704790f,
			0.412574f, 0.356113f, 0.759300f, 0.268286f, 0.146489f, 0.639068f, 0.723776f, 0.836549f, 0.423214f, 0.814626f, 0.661948f, 0.137238f, 0.661232f, 0.188423f, 0.687164f, 0.051186f,
            0.914162f, 0.520019f, 0.767734f, 0.054342f, 0.624323f, 0.719543f, 0.335802f, 0.206157f, 0.607567f, 0.181137f, 0.747335f, 0.760382f, 0.366467f, 0.226619f, 0.361422f, 0.408920f,
			0.360232f, 0.381659f, 0.306302f, 0.622548f, 0.008147f, 0.635085f, 0.418211f, 0.269839f, 0.376679f, 0.054137f, 0.309206f, 0.570472f, 0.052342f, 0.154050f, 0.420058f, 0.204137f,
            0.467768f, 0.176715f, 0.450595f, 0.619221f, 0.425016f, 0.995825f, 0.011983f, 0.074281f, 0.484168f, 0.251354f, 0.092460f, 0.352795f, 0.222918f, 0.116395f, 0.169998f, 0.917204f,
			0.738899f, 0.218233f, 0.510303f, 0.956154f, 0.743618f, 0.840431f, 0.062318f, 0.167190f, 0.013384f, 0.122684f, 0.970399f, 0.252966f, 0.877565f, 0.878167f, 0.659990f, 0.828444f,
            0.809497f, 0.463703f, 0.700541f, 0.532644f, 0.358658f, 0.485886f, 0.397510f, 0.587105f, 0.607922f, 0.337230f, 0.183420f, 0.324520f, 0.110377f, 0.201604f, 0.586692f, 0.539287f,
			0.845354f, 0.722808f, 0.525183f, 0.614981f, 0.851841f, 0.109236f, 0.777885f, 0.830234f, 0.387641f, 0.970569f, 0.248360f, 0.222899f, 0.689126f, 0.457795f, 0.646213f, 0.541457f,
            0.012079f, 0.213128f, 0.221760f, 0.318560f, 0.248570f, 0.725590f, 0.559436f, 0.515782f, 0.421681f, 0.324591f, 0.669527f, 0.920388f, 0.872312f, 0.452463f, 0.138574f, 0.766659f,
			0.445420f, 0.331018f, 0.256544f, 0.085236f, 0.317305f, 0.616007f, 0.885746f, 0.951730f, 0.761568f, 0.101830f, 0.026980f, 0.379081f, 0.778204f, 0.303125f, 0.842091f, 0.956545f,
            0.339792f, 0.660836f, 0.611802f, 0.045993f, 0.741682f, 0.863271f, 0.344477f, 0.906810f, 0.249075f, 0.048364f, 0.765697f, 0.677216f, 0.139675f, 0.069926f, 0.739581f, 0.063157f,
			0.800349f, 0.521348f, 0.362248f, 0.963067f, 0.686497f, 0.971570f, 0.609351f, 0.508110f, 0.656020f, 0.947443f, 0.716425f, 0.048459f, 0.680347f, 0.877975f, 0.874616f, 0.791551f,
            0.825693f, 0.106665f, 0.233382f, 0.725843f, 0.240272f, 0.276939f, 0.554138f, 0.322744f, 0.202249f, 0.407597f, 0.110998f, 0.637577f, 0.239774f, 0.974333f, 0.239647f, 0.765885f,
			0.769660f, 0.593066f, 0.142948f, 0.238623f, 0.134331f, 0.577788f, 0.384977f, 0.119127f, 0.583751f, 0.755089f, 0.450776f, 0.770074f, 0.303827f, 0.970218f, 0.809203f, 0.116695f,
            0.735454f, 0.013013f, 0.000659f, 0.887968f, 0.456439f, 0.789520f, 0.378604f, 0.368727f, 0.838967f, 0.205754f, 0.998544f, 0.067883f, 0.765159f, 0.950196f, 0.337813f, 0.245447f,
			0.478228f, 0.281824f, 0.518263f, 0.714497f, 0.816484f, 0.688991f, 0.989210f, 0.279150f, 0.962190f, 0.144469f, 0.937260f, 0.840014f, 0.886744f, 0.388978f, 0.746467f, 0.689903f,
            0.295462f, 0.707838f, 0.467594f, 0.397633f, 0.050383f, 0.725771f, 0.248658f, 0.613526f, 0.006592f, 0.791893f, 0.752470f, 0.516905f, 0.802497f, 0.318101f, 0.054779f, 0.182632f,
			0.208239f, 0.028364f, 0.016549f, 0.822479f, 0.467512f, 0.632887f, 0.672444f, 0.452504f, 0.890913f, 0.945280f, 0.820986f, 0.372790f, 0.371278f, 0.975212f, 0.044100f, 0.713906f,
            0.715411f, 0.602545f, 0.065763f, 0.787931f, 0.339610f, 0.221024f, 0.277892f, 0.293257f, 0.542782f, 0.686109f, 0.115156f, 0.658741f, 0.980804f, 0.091177f, 0.728526f, 0.256006f,
			0.873865f, 0.278029f, 0.287839f, 0.516331f, 0.700478f, 0.061656f, 0.945882f, 0.545822f, 0.384741f, 0.928869f, 0.037488f, 0.165914f, 0.316321f, 0.078455f, 0.155139f, 0.516342f,
        };
    }
}