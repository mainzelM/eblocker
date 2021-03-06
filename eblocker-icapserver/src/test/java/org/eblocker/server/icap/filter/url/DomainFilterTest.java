/*
 * Copyright 2020 eBlocker Open Source UG (haftungsbeschraenkt)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the EUPL
 * (the "License"); You may not use this work except in compliance with
 * the License. You may obtain a copy of the License at:
 *
 *   https://joinup.ec.europa.eu/page/eupl-text-11-12
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package org.eblocker.server.icap.filter.url;

import org.eblocker.server.common.transaction.Decision;
import org.eblocker.server.common.transaction.TransactionContext;
import org.eblocker.server.icap.filter.Filter;
import org.eblocker.server.icap.filter.FilterType;
import org.eblocker.server.icap.filter.TestContext;
import org.junit.Assert;
import org.junit.Test;

public class DomainFilterTest {

    @Test
    public void test() {
        String url = "http://world.most.annoying.ads/image/large/overlay";
        Assert.assertEquals(Decision.BLOCK, filter("world.most.annoying.ads", FilterType.BLOCK, url));
        Assert.assertEquals(Decision.BLOCK, filter("most.annoying.ads", FilterType.BLOCK, url));
        Assert.assertEquals(Decision.BLOCK, filter("annoying.ads", FilterType.BLOCK, url));
        Assert.assertEquals(Decision.NO_DECISION, filter("world.annoying.ads", FilterType.BLOCK, url));
    }

    private Decision filter(String domain, FilterType type, String url) {
        TransactionContext context = new TestContext(url);
        Filter filter = UrlFilterFactory.getInstance()
                .setStringMatchType(StringMatchType.DOMAIN)
                .setDomain(domain)
                .setType(type)
                .build();
        return filter.filter(context).getDecision();
    }

}
