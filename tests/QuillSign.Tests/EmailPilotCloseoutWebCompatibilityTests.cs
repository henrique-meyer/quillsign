using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Email.Pilot;

namespace QuillSign.Tests;

public sealed class EmailPilotCloseoutWebCompatibilityTests
{
    [Fact]
    public void Shared_input_purpose_is_role_independent_and_cannot_change_retained_bytes_silently()
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();
        var legacy=JsonSerializer.Serialize(h.Options.Capture());Assert.DoesNotContain("WebInput",legacy);
        h.Options.PrivateConfigurationSet="private";h.Options.HostRole=EmailPilotCloseoutHostRole.Web;
        h.Options.WebInput=new(){Sha256=new string('a',64),Bytes=32,Filename="synthetic.pdf"};
        var web=JsonSerializer.Serialize(h.Options.Capture());
        h.Options.HostRole=EmailPilotCloseoutHostRole.Pass;Assert.Equal(web,JsonSerializer.Serialize(h.Options.Capture()));
        h.Options.HostRole=EmailPilotCloseoutHostRole.Handoff;h.Options.Enabled=false;Assert.Equal(web,JsonSerializer.Serialize(h.Options.CaptureReceiptConfiguration()));
        h.Options.WebInput.Bytes++;Assert.NotEqual(web,JsonSerializer.Serialize(h.Options.CaptureReceiptConfiguration()));
    }
    [Theory]
    [InlineData("Web",false)][InlineData("Web",true)]
    public void Main_cannot_register_positive_Web_even_through_explicit_Pass_parameter(string role,bool pass)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{
            {"EmailPilot:Closeout:HostRole",role},{"EmailPilot:Closeout:PrivateConfigurationSet","private"}}).Build();
        Assert.Throws<InvalidOperationException>(()=>new ServiceCollection().AddRestrictedEmailPilotRuntime(config,privatePass:pass));
    }
    [Fact]
    public void Invalid_input_or_legacy_relabelling_refuses()
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Options.WebInput=new(){Sha256=new string('a',64),Bytes=32,Filename="synthetic.pdf"};
        Assert.Throws<InvalidOperationException>(h.Options.Validate);
        Assert.Throws<InvalidOperationException>(()=>h.Options.CaptureReceiptConfiguration());
        h.Options.HostRole=EmailPilotCloseoutHostRole.Handoff;h.Options.Enabled=false;h.Options.PrivateConfigurationSet="private";
        h.Options.WebInput.Filename="../synthetic.pdf";Assert.Throws<InvalidOperationException>(()=>h.Options.CaptureReceiptConfiguration());
    }
}
