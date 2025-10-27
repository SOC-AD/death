rule rule_name
{
    meta:
        description = "<word>"
        author = "<Aaron Dellamano>"
        date = "<October 17, 2025>"
        hash = "<hash>"
    strings:
        $s1 = "a"
    condition:
        $s1
}