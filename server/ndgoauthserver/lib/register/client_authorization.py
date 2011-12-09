class ClientAuthorization(object):
    """
    Represents authorizations granted by the resource owner to clients.
    """
    def __init__(self, user, client_id, scope, is_authorized):
        self.user = user
        self.client_id = client_id
        self.scope = scope
        self.is_authorized = is_authorized

    def eq_authz_basis(self, other):
        return ((self.user == other.user)
                and (self.client_id == other.client_id)
                and (self.scope == other.scope))

    def __repr__(self):
        return ("user: %s  client_id: %s  scope: %s  granted: %s" % (self.user, self.client_id, self.scope, self.is_authorized))

class ClientAuthorizationRegister(object):
    """
    Register of authorizations granted by the resource owner to clients.
    """
    def __init__(self):
        self.register = {}

    def add_client_authorization(self, client_authorization):
        user_authorizations = self.register.setdefault(client_authorization.user, {})
        client_authorizations = user_authorizations.setdefault(client_authorization.client_id, [])
        for auth in client_authorizations:
            if auth.eq_authz_basis(client_authorization):
                auth.is_authorized = client_authorization.is_authorized

        user_authorizations[client_authorization.client_id].append(client_authorization)


    def is_client_authorized_by_user(self, user, client_id, scope):
        client_authorization = ClientAuthorization(user, client_id, scope, True)
        user_authorizations = self.register.get(user)
        if user_authorizations:
            client_authorizations = user_authorizations.get(client_id, [])
            # Assume small number of authorization types per user/client (probably typically one).
            for auth in client_authorizations:
                if auth.eq_authz_basis(client_authorization):
                    return auth.is_authorized
        return None

    def __repr__(self):
        s = []
        for u, uv in self.register.iteritems():
            for c, cv in uv.iteritems():
                s.append(cv.__repr__())
        return ' '.join(s)
