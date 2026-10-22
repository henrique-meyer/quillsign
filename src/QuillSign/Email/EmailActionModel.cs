namespace QuillSign.Email;

public sealed record EmailActionModel(Uri Link, string Label, bool IncludeFallback = true);
