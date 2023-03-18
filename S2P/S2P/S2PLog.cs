using System.Data;

namespace S2P
{
    public class S2PLog
    {
        private readonly DataTable Table;
        private readonly List<Dictionary<string, string>> Comments;
        public readonly string[] ColumnNames = new string[] { "freq", "magS11", "angS11", "magS21", "angS21", "magS12", "angS12", "magS22", "angS22" };
        private const int S2PPadding = 16;
        public bool TouchstoneVersion2 { get; set; } = true;
        public S2PLog()
        {
            Table = new DataTable();

            foreach (string columnName in ColumnNames)
            {
                DataColumn column;

                column = new DataColumn
                {
                    ColumnName = columnName,
                    DataType = typeof(double),
                    AllowDBNull = false,
                    DefaultValue = 0
                };
                Table.Columns.Add(column);
            }

            Comments = new List<Dictionary<string, string>> { };
        }
        public void ClearDataRows()
        {
            Table.Rows.Clear();
        }
        public void SetFrequencies(List<double> frequencies)
        {
            ClearDataRows();
            foreach (double frequency in frequencies)
            {
                DataRow row;
                row = Table.NewRow();
                row["freq"] = frequency;
                Table.Rows.Add(row);
            }
        }

        public void SetColumnData(string columnName, List<double> data)
        {
            if (data.Count != Table.Rows.Count)
                throw new Exception("Data length must match frequency length");

            if (!Table.Columns.Contains(columnName))
                throw new Exception(columnName + " is not a valid column name");

            for (int i = 0; i < data.Count; i++)
            {
                Table.Rows[i][columnName] = data[i];
            }
        }
        public void ClearComments()
        {
            Comments.Clear();
        }
        //public void AddComments(ILogStateInformation source)
        //{
        //    Comments.Add(source.StateInformation);
        //}
        public void AddComments(Dictionary<string, string> comments)
        {
            Comments.Add(comments);
        }
        public void Save(string filename)
        {
            int dataLength = Table.Rows.Count;

            // Delete the file if it exists.
            if (File.Exists(filename))
            {
                File.Delete(filename);
            }

            // Create the file.
            using StreamWriter fs = new(filename);
            // Write all comments
            foreach (var collection in Comments)
            {
                foreach (var comment in collection)
                {
                    fs.WriteLine("! " + comment.Key + " = " + comment.Value);
                }
            }

            if (TouchstoneVersion2)
            {
                fs.WriteLine("[Version] 2.0"); //Touchstone version 2
            }
            fs.WriteLine("# MHz S DB R 50"); // S params using DB for magnitude and Degrees for phase
            if (TouchstoneVersion2)
            {
                fs.WriteLine("[Number of Ports] 2");
                fs.WriteLine("[Two-Port Data Order] 21_12");
                fs.WriteLine("[Number of Frequencies] " + dataLength);
            }

            // Write column names
            bool first = true;
            foreach (DataColumn column in Table.Columns)
            {
                string tempString;
                if (first)
                {
                    tempString = "! " + column.ColumnName;
                    first = false;
                }
                else
                {
                    tempString = column.ColumnName;
                }

                fs.Write(tempString.PadRight(S2PPadding));
            }
            fs.WriteLine();

            // Write data
            foreach (DataRow row in Table.Rows)
            {
                foreach (DataColumn column in Table.Columns)
                {
                    object value = row[column.ColumnName];
                    if (value == DBNull.Value)
                        fs.Write("0 ".PadRight(S2PPadding));
                    else
                        fs.Write(((double)value).ToString("E7").PadRight(S2PPadding));
                }
                fs.WriteLine();
            }

            fs.Close();
        }
    }
}