# agent-infra-security demo
# Run: vhs assets/demo.tape

Output assets/demo.gif

Set FontSize 22
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

# Scene 1: Install with npx skills
Type "# Install the security skills"
Enter
Sleep 500ms

Hide
Type "echo ''"
Enter
Show

Type "npx skills add makash/agent-infra-security"
Enter

Hide
Type "echo ''"
Enter
Show

Sleep 1500ms

# Scene 2: Show what you get
Type ""
Enter
Sleep 300ms
Type "# Two skills installed:"
Enter
Type "#   pypi-supply-chain-response    — deep PyPI triage"
Enter
Type "#   supply-chain-security-check   — multi-ecosystem scan"
Enter
Sleep 2s

# Scene 3: Show the manual check
Type ""
Enter
Sleep 300ms
Type "# Or skip the agent. Check right now:"
Enter
Sleep 500ms

Type 'pip show litellm | grep -E "^(Name|Version|Location)"'
Enter

Hide
Type "echo ''"
Enter
Show

Sleep 1s

Type "pipdeptree -r -p litellm"
Enter

Hide
Type "echo ''"
Enter
Show

Sleep 1s

Type "# Find malicious .pth startup hooks"
Enter
Sleep 300ms
Type 'find "$SITE" -name "*.pth" -exec grep -l "base64\|exec\|eval" {} \;'
Enter

Hide
Type "echo ''"
Enter
Show

Sleep 2s

Sleep 2s
