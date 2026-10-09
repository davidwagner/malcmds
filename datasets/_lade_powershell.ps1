# Parse source text only. Never invoke, dot-source, or evaluate source AST nodes.
$ErrorActionPreference = 'Stop'
while ($null -ne ($line = [Console]::ReadLine())) {
    $request = ConvertFrom-Json -InputObject $line
    $text = $request.text
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    $commands = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true))
    $result = @()
    foreach ($command in $commands) {
        $elements = @($command.CommandElements)
        if ($elements.Count -eq 0) { continue }
        $values = @()
        foreach ($element in $elements) {
            if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                $element -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                $values += $element.Value
            } else {
                $values += $element.Extent.Text
            }
        }
        $other = @()
        foreach ($token in $(if ($request.other) { $tokens } else { @() })) {
            if ($token.Kind -eq 'EndOfInput' -or $token.Kind -eq 'NewLine') { continue }
            $included = $false
            foreach ($element in $elements) {
                if ($token.Extent.StartOffset -ge $element.Extent.StartOffset -and
                    $token.Extent.EndOffset -le $element.Extent.EndOffset) {
                    $included = $true
                    break
                }
            }
            if (-not $included) { $other += $token.Text }
        }
        $arguments = @()
        if ($values.Count -gt 1) { $arguments = @($values[1..($values.Count - 1)]) }
        $result += @{ program = $values[0]; arguments = $arguments; other = $other }
    }
    # Parse errors are expected in partial publisher script blocks; valid
    # CommandAst nodes remain usable and source text remains unchanged.
    [Console]::WriteLine((ConvertTo-Json -InputObject @($result) -Depth 20 -Compress))
}
