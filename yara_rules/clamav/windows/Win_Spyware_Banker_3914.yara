rule Win_Spyware_Banker_3914
{
strings:
	$a0 = { 1fd1f4b76e5596fb060ca40872d139505b394950be412ca0732e80be4860d44ac2ac541aa5378b21dc196de1729b54756be2d5ee8f118a55b5b5f1668f6944d4e97e1fdccfee154d063e1c3ccefe3e35f56f129dff016f8575ae6ea189259ce33c53c4a182ff82bdb7efb7988d6fc404f78a8ce7536d7d685728260b01568ef821571a2fb13b88bd7d16b138 }

condition:
	$a0
}

        