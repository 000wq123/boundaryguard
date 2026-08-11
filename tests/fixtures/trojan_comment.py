# Fixture: Trojan Source comment-out attack (CVE-2021-42574)
# The RLI/PDI isolate pair below makes the "if False:" render inside the
# comment while it is logically executable code.
if True:  # ⁧ if False: ⁩
    print("branch executes")
