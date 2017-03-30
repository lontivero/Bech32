using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bech32
{
	public class Bech32Tests
	{
		private static string[] VALID_CHECKSUM =
		{
			"A12UEL5L",
			"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
			"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
			"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
			"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
		};

		public void ValidateValidChecksum()
		{
			var encoder = new Bech32();
			foreach (var test in VALID_CHECKSUM)
			{
				byte[] hrp;
				Bech32.Bech32Decode(test, out hrp);
				if (hrp == null) throw new Exception();
				var pos = test.LastIndexOf('1');
				var test2 = test.Substring(0, pos + 1) + ((test[pos + 1]) ^ 1) + test.Substring(pos + 2);
				try
				{
					Bech32.Bech32Decode(test2, out hrp);
					throw new Exception();
				}
				catch (FormatException e)
				{

				}
			}
		}


		private static string[][] VALID_ADDRESS = {
			new	[] { "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
			new [] { "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7","00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
			new [] { "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
			new [] { "BC1SW50QA3JX3S", "9002751e"},
			new [] { "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "8210751e76e8199196d454941c45d1b3a323"},
			new [] { "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
		};

		public void ValidAddress()
		{
			foreach (var address in VALID_ADDRESS)
			{
				byte witVer;
				var hrp = "bc";
				byte[] witProg;
				try
				{
					witProg = Bech32.Decode(hrp, address[0], out witVer);
				}
				catch
				{
					hrp = "tb";
					witProg = Bech32.Decode(hrp, address[0], out witVer);
				}

				var scriptPubkey = Scriptpubkey(witVer, witProg);
				var hex = string.Join("", scriptPubkey.Select(x => x.ToString("x2")));
				if(hex != address[1])
					throw new Exception();
				var addr = Bech32.Encode(Encoding.ASCII.GetBytes(hrp), witVer, witProg);
				if(address[0].ToLowerInvariant() != addr) throw new Exception();
			}
		}


		private static string[] INVALID_ADDRESS = {
			"tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
			"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
			"BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
			"bc1rw5uspcuh",
			"bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
			"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
			"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
			"tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
			"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
		};

		/*
			def test_invalid_address(self):
				"""Test whether invalid addresses fail to decode."""
				for test in INVALID_ADDRESS:
					witver, _ = segwit_addr.decode("bc", test)
					self.assertIsNone(witver)
					witver, _ = segwit_addr.decode("tb", test)
					self.assertIsNone(witver) 
		*/

		public void InvalidAddress()
		{
			foreach (var test in INVALID_ADDRESS)
			{
				byte witver;
				try
				{
					Bech32.Decode("bc", test, out witver);
					throw new Exception();
				}
				catch { }
				try
				{
					Bech32.Decode("tb", test, out witver);
					throw new Exception();
				}
				catch { }
			}
		}


		private static byte[] Scriptpubkey(byte witver, byte[] witprog)
		{
			var v = witver > 0 ? witver + 0x80 : 0;
			return ArrayUtils.Concat(new [] {(byte)v, (byte) witprog.Length}, witprog);
		}
	}
}
