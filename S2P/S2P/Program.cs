using Microsoft.VisualBasic.FileIO;

namespace S2P
{
    public class S2PApp
    {
        static void Main()
        {
            var s2plog = new S2PLog
            {
                TouchstoneVersion2 = false
            };

            var timestamp = DateTime.Now;

            Console.Write("S2P File Path: ");
            var path = Console.ReadLine() ?? throw new Exception("null file");
            TextFieldParser parser = new(path)
            {
                TextFieldType = FieldType.Delimited
            };
            parser.SetDelimiters(" ");
            string?[] header = new string[11];
            List<double> magS11 = new();
            List<double> magS21 = new();
            List<double> magS12 = new();
            List<double> magS22 = new();
            List<double> angS11 = new();
            List<double> angS21 = new();
            List<double> angS12 = new();
            List<double> angS22 = new();
            List<double> freqs = new();
            List<double> SparamValues = new();

            for (int i = 0; i < 11; i++)
            {
                //Processing row
                header[i] = parser.ReadLine();
            }
            while (!parser.EndOfData)
            {
                var fields = parser.ReadFields();
                if(fields != null)
                {
                    foreach (string field in fields)
                    {
                        if (!field.Contains(' ') && field != "")
                        {
                            SparamValues.Add(Convert.ToDouble(field));
                        }
                    }
                }
            }
            for (int i = 0; i < SparamValues.Count; i += 9)
            {

                freqs.Add(SparamValues[i]);
                magS11.Add(SparamValues[i + 1]);
                angS11.Add(SparamValues[i + 2]);

                magS21.Add(SparamValues[i + 3]);
                angS21.Add(SparamValues[i + 4]);

                magS12.Add(SparamValues[i + 5]);
                angS12.Add(SparamValues[i + 6]);

                magS22.Add(SparamValues[i + 7]);
                angS22.Add(SparamValues[i + 8]);
            }
            Console.Write("Interpolation Factor: ");
            int interpolFactor = Convert.ToInt32(Console.ReadLine());
            List<double> Interpolatedfreqs = InterpolateData(freqs, interpolFactor);
            List<double> InterpolatedmagS11 = InterpolateData(magS11, interpolFactor);
            List<double> InterpolatedangS11 = InterpolateData(angS11, interpolFactor);
            List<double> InterpolatedmagS21 = InterpolateData(magS21, interpolFactor);
            List<double> InterpolatedangS21 = InterpolateData(angS21, interpolFactor);
            List<double> InterpolatedmagS12 = InterpolateData(magS12, interpolFactor);
            List<double> InterpolatedangS12 = InterpolateData(angS12, interpolFactor);
            List<double> InterpolatedmagS22 = InterpolateData(magS22, interpolFactor);
            List<double> InterpolatedangS22 = InterpolateData(angS22, interpolFactor);

            s2plog.SetFrequencies(Interpolatedfreqs);
            s2plog.SetColumnData("magS11", InterpolatedmagS11);
            s2plog.SetColumnData("angS11", InterpolatedangS11);

            s2plog.SetColumnData("magS21", InterpolatedmagS21);
            s2plog.SetColumnData("angS21", InterpolatedangS21);

            s2plog.SetColumnData("magS12", InterpolatedmagS12);
            s2plog.SetColumnData("angS12", InterpolatedangS12);

            s2plog.SetColumnData("magS22", InterpolatedmagS22);
            s2plog.SetColumnData("angS22", InterpolatedangS22);

            s2plog.AddComments(new Dictionary<string, string> { { "Interpolation Time Stamp", $"{timestamp:MM/dd/yyyy hh/mm/ss tt}" } });
            s2plog.AddComments(new Dictionary<string, string> { {"Custom Data Interpolation Factor", $"{interpolFactor}"} });

            string fileName = $"INTERPOLATED_{path[(path.LastIndexOf('\\') + 1)..]}";
            string s2pFilePath = $"{path[..(path.LastIndexOf('\\') + 1)]}{fileName}";
            s2plog.Save(s2pFilePath);
        }
        public static List<double> InterpolateData(List<double> inputData, int interpolationFactor)
        {
            List<double> outputData = new();

            for (int i = 0; i < inputData.Count - 1; i++)
            {
                double start = inputData[i];
                double end = inputData[i + 1];

                outputData.Add(start);

                double interval = (end - start) / (interpolationFactor + 1);
                for (int j = 1; j <= interpolationFactor; j++)
                {
                    double value = start + (j * interval);
                    outputData.Add(value);
                }
            }

            outputData.Add(inputData[^1]);

            return outputData;
        }
    }
}
