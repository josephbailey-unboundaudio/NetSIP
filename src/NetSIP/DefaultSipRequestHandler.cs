namespace NetSIP;

/// <summary>Responds to OPTIONS and optional REGISTER/INVITE requests.</summary>
public sealed class DefaultSipRequestHandler : ISipRequestHandler
{
    /// <summary>
    /// Optional registration handler for REGISTER requests.
    /// </summary>
    private readonly RegisterSipRequestHandler? _registerHandler;
    /// <summary>
    /// Optional dialplan handler for INVITE requests.
    /// </summary>
    private readonly SipInviteRequestHandler? _inviteHandler;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultSipRequestHandler"/> class
    /// that handles only OPTIONS requests.
    /// </summary>
    public DefaultSipRequestHandler()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultSipRequestHandler"/> class
    /// that handles OPTIONS and REGISTER requests.
    /// </summary>
    /// <param name="registerHandler">The handler for REGISTER requests.</param>
    public DefaultSipRequestHandler(RegisterSipRequestHandler registerHandler)
        : this(
            registerHandler ?? throw new ArgumentNullException(nameof(registerHandler)),
            inviteHandler: null)
    {
    }

    /// <summary>Initializes a handler that supports OPTIONS and INVITE.</summary>
    /// <param name="inviteHandler">The handler for INVITE requests.</param>
    public DefaultSipRequestHandler(SipInviteRequestHandler inviteHandler)
        : this(
            registerHandler: null,
            inviteHandler ?? throw new ArgumentNullException(nameof(inviteHandler)))
    {
    }

    /// <summary>Initializes a handler with optional REGISTER and INVITE support.</summary>
    /// <param name="registerHandler">The optional handler for REGISTER requests.</param>
    /// <param name="inviteHandler">The optional handler for INVITE requests.</param>
    public DefaultSipRequestHandler(
        RegisterSipRequestHandler? registerHandler,
        SipInviteRequestHandler? inviteHandler)
    {
        _registerHandler = registerHandler;
        _inviteHandler = inviteHandler;
    }

    /// <summary>
    /// Handles a SIP request by routing it to the appropriate handler.
    /// Supports OPTIONS and optionally REGISTER and INVITE. Rejects other methods with 501.
    /// </summary>
    /// <param name="context">The request context.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The selected handler operation.</returns>
    public ValueTask HandleAsync(SipRequestContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SipMessageView message = context.Message;

        if (AsciiUtilities.EqualsIgnoreCase(message.Method, "OPTIONS"u8))
        {
            if (!context.Response.WriteOptionsOk(
                    message,
                    allowRegister: _registerHandler is not null,
                    allowInvite: _inviteHandler is not null))
            {
                context.Response.WriteError(400);
            }
        }
        else if (_registerHandler is not null &&
            AsciiUtilities.EqualsIgnoreCase(message.Method, "REGISTER"u8))
        {
            _registerHandler.Handle(context, message);
        }
        else if (_inviteHandler is not null &&
            AsciiUtilities.EqualsIgnoreCase(message.Method, "INVITE"u8))
        {
            return _inviteHandler.HandleAsync(context, cancellationToken);
        }
        else if (!context.Response.WriteResponse(501, "Not Implemented"u8, message))
        {
            context.Response.WriteError(400);
        }

        return ValueTask.CompletedTask;
    }
}
