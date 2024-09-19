﻿using System;
using System.Windows.Forms;

namespace OfflinePasswordCheck
{
    public partial class ProgressDisplay : Form
    {
        public bool UserTerminated { get; set; }

        public ProgressDisplay()
        {
            InitializeComponent();
            UserTerminated = false;
            ShowInTaskbar = true;
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
