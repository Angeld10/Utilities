using System;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.FileIO;

namespace S2P
{
    public class S2PApp
    {
        static void Main()
        {
            var path = Console.ReadLine();
            if (path == null) throw new Exception("null file");
            TextFieldParser parser = new(path);
            parser.TextFieldType = FieldType.Delimited;
            parser.SetDelimiters("  ");
            string?[] header = new string[11];
            for (int i = 0; i < 11; i++)
            {
                //Processing row
                header[i] = parser.ReadLine();
            }
            for (int i = 0; i < 50; i++)
            {
                var fields = parser.ReadFields();
                if(fields != null)
                {
                    foreach (string field in fields)
                    {
                        Console.WriteLine(i);
                        Console.WriteLine(field);
                    }
                }
                
            }
                
        }
    }
}
