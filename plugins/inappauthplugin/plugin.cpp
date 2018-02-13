/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)

Q_LOGGING_CATEGORY(lcSailfishSecretsPluginInapp, "org.sailfishos.secrets.plugin.authentication.inapp", QtWarningMsg)

using namespace Sailfish::Secrets;

Daemon::Plugins::InAppPlugin::InAppPlugin(QObject *parent)
    : AuthenticationPlugin(parent)
{
}

Daemon::Plugins::InAppPlugin::~InAppPlugin()
{
}


Result
Daemon::Plugins::InAppPlugin::beginAuthentication(
            uint callerPid,
            qint64 requestId)
{
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    return Result(Result::OperationRequiresSystemUserInteraction,
                  QLatin1String("In-App plugin cannot properly authenticate the user"));
}

Result
Daemon::Plugins::InAppPlugin::beginUserInputInteraction(
            uint callerPid,
            qint64 requestId,
            const Sailfish::Secrets::InteractionParameters &interactionParameters,
            const QString &interactionServiceAddress)
{
    InteractionRequestWatcher *watcher = new InteractionRequestWatcher(this);
    watcher->setRequestId(requestId);
    watcher->setCallerPid(callerPid);
    watcher->setInteractionParameters(interactionParameters);
    watcher->setInteractionServiceAddress(interactionServiceAddress);
    connect(watcher, static_cast<void (InteractionRequestWatcher::*)(quint64)>(&InteractionRequestWatcher::interactionRequestFinished),
            this, &Daemon::Plugins::InAppPlugin::interactionRequestFinished);
    connect(watcher, &InteractionRequestWatcher::interactionRequestResponse,
            this, &Daemon::Plugins::InAppPlugin::interactionRequestResponse);

    if (!watcher->connectToInteractionService()) {
        watcher->deleteLater();
        return Result(
                    Result::InteractionServiceUnavailableError,
                    QString::fromUtf8("Unable to connect to ui service"));
    }

    if (!watcher->sendInteractionRequest()) {
        watcher->deleteLater();
        return Result(
                    Result::InteractionServiceRequestFailedError,
                    QString::fromUtf8("Unable to send interaction request to ui service"));
    }

    m_requests.insert(requestId, watcher);
    return Result(Result::Pending);
}

void
Daemon::Plugins::InAppPlugin::interactionRequestResponse(
        quint64 requestId,
        const InteractionResponse &response)
{
    InteractionRequestWatcher *watcher = m_requests.value(requestId);
    if (watcher == Q_NULLPTR) {
        qCDebug(lcSailfishSecretsPluginInapp) << "Unknown ui request response:" << requestId;
        return;
    }

    emit userInputInteractionCompleted(
                watcher->callerPid(),
                watcher->requestId(),
                watcher->interactionParameters(),
                watcher->interactionServiceAddress(),
                response.result(),
                response.responseData());

    watcher->finishInteractionRequest();
}

void
Daemon::Plugins::InAppPlugin::interactionRequestFinished(
        quint64 requestId)
{
    InteractionRequestWatcher *watcher = m_requests.value(requestId);
    if (watcher == Q_NULLPTR) {
        qCDebug(lcSailfishSecretsPluginInapp) << "Unknown ui request finished:" << requestId;
        return;
    }
    watcher->disconnectFromInteractionService();
    watcher->deleteLater();
}
