rule Win_Spyware_Banker_4356
{
strings:
	$a0 = { de526b3d17f3ebe2c5db7e56c5f47acd5636accf57c2a5ba3a0ae6f5f93b275bd666f3c146abf1ff058f527f850595bdf61477e3fc0df0951639af3a7b3b95589b486e8f8218775b5d43357cb251f41535c7dac0013dc8708927690a4de1fefa1bcd9cf65bb65c67e789bb1b7692db01ce4323e56f2e6e3942114715d6e1fa44beaf9c4fb2005287a6073cee }

condition:
	$a0
}

        