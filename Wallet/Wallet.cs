using System.IO;

namespace DLT
{
    public class Wallet
    {
        public string id;
        public ulong balance;
        public string data;

        public Wallet()
        {
            id = "";
            balance = 0;
            data = "";
        }

        public Wallet(string w_id, ulong w_balance)
        {
            id = w_id;
            balance = w_balance;
            data = "";
        }
        
        public Wallet(Wallet wallet)
        {
            id = wallet.id;
            balance = wallet.balance;
            data = wallet.data;
        }

        public Wallet(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    id = reader.ReadString();
                    balance = reader.ReadUInt64();
                    data = reader.ReadString();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(id);
                    writer.Write(balance);
                    writer.Write(data);
                }
                return m.ToArray();
            }
        }

        // Calculate the wallet checksum based on it's contents
        public string calculateChecksum()
        {
            string baseData = id + balance + data;
            return Crypto.sha256(baseData);
        }



    }
}