# find_end_elam
Script which searches whole fabric for source destination IP, finds switch nodes they live on and perform ELAM on them,
saving results to the APIC.


Meant to be run from APIC
For the sake of simplicity it's expected to just create a scrip on APIC manually.
To do so, on APIC :
vi <FILENAME>
press "i"
copy-paste code of the find_end_elam
press <ESC>
press :qw
change permissions to make file executible by running "chmod +x <FILENAME>"
Now it's ready to be run.