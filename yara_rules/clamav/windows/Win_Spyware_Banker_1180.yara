rule Win_Spyware_Banker_1180
{
strings:
	$a0 = { 13b066127b94fb2b648b6409a2e246f41e579bcf37faf8f5c47467fe22485219a28240dade48cb1a521cc93ac563cbeea1c9a786f7c766cab36d595f5ea5b150646a3c9dad26df8beb0e0d3bfef8ba5259bd0b9701e7f0eb8f46 }

condition:
	$a0
}

        
