rule Win_Spyware_Banker_1955
{
strings:
	$a0 = { a627bf93bd83bd15607b11227aec9d35d190b8fc4f8c0d8187e5bdc8ceef60ef6ce7d15650b40e282df9558ad401cca781a99584e18f58121ddc7958eb0b5d3e2c965d2f60b1fce60f502c5f684bab0a7e9c7ffc4afa01dcbffc13c77df10771e7eb15dcd81dcba7bee0b82fbd84b87784c0bd9b037aed0b8edbbc15707ff092 }

condition:
	$a0
}

        
