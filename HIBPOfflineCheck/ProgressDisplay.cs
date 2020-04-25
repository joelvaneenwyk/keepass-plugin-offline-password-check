using System;
using System.Windows.Forms;

namespace HIBPOfflineCheck
{
    public partial class ProgressDisplay : Form
    {
        public bool UserTerminated { get; set; }

        public ProgressDisplay()
        {
            InitializeComponent();
            UserTerminated = false;
        }

        private void buttonCancel_Click(object sender, EventArgs e)
        {
            UserTerminated = true;
            Close();
        }

        private void ProgressDisplay_FormClosing(object sender, FormClosingEventArgs e)
        {
            UserTerminated = true;
        }
    }
}
