rule Win_Spyware_Banker_3264
{
strings:
	$a0 = { 7e537271e3614b3894c9971e7698f62364a4cde9c32cbd72ac8ecbc623b0e9a9e27c9d8e360381d8620c5b4bd4d8c3b6470b6a23c1d41deffb6e4ee6a46a1ced74b242ef0cfd8b38f45ead331f653c133fbf04e477196bbe1eb206255fce39f9b3a828f88320eae77a13d18093bdc13012ccbe719fc637d6559bad4048cdb3778b233892df4a265c39fb2c61 }

condition:
	$a0
}

        