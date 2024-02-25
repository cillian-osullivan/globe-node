// Copyright (c) 2009-2018 The Globe Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?req-dontexist="));
    QVERIFY(!GUIUtil::parseGlobeURI(uri, &rv));

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?dontexist="));
    QVERIFY(GUIUtil::parseGlobeURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseGlobeURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=0.001"));
    QVERIFY(GUIUtil::parseGlobeURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=1.001"));
    QVERIFY(GUIUtil::parseGlobeURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=100&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseGlobeURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseGlobeURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseGlobeURI("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseGlobeURI(uri, &rv));

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseGlobeURI(uri, &rv));

    uri.setUrl(QString("globe:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseGlobeURI(uri, &rv));
}
