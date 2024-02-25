// Copyright (c) 2011-2020 The Globe Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBE_QT_GLOBEADDRESSVALIDATOR_H
#define GLOBE_QT_GLOBEADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class GlobeAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit GlobeAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** Globe address widget validator, checks for a valid globe address.
 */
class GlobeAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit GlobeAddressCheckValidator(QObject *parent, bool allow_stakeonly=false);

    State validate(QString &input, int &pos) const override;
    bool m_allow_stakeonly;
};

#endif // GLOBE_QT_GLOBEADDRESSVALIDATOR_H
