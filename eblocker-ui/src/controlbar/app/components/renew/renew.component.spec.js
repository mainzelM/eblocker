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
import 'angular-mocks';

/* jshint expr:true */
describe('App controlbar; Component: Renew', function() {
    // ** template cache: so that calls for templates get the 'real' HTML file.
    beforeEach(angular.mock.module('template.controlbar.app'));
    beforeEach(angular.mock.module('eblocker.controlbar'));

    var $componentController, $q, $rootScope, ctrl, mockLoggerService, mockDeviceList;

    mockLoggerService = {
        info: function(param) {
            // nothing to do for now
        },
        error: function(param) {
            // nothing to do for now
        }
    };

    beforeEach(angular.mock.module(function($provide, $translateProvider) {
        $provide.value('logger', mockLoggerService);
        // Workaround angular-translate issue:
        // https://angular-translate.github.io/docs/#/guide/22_unit-testing-with-angular-translate
        $translateProvider.translations('en', {});
    }));

    beforeEach(inject(function(_$componentController_, _$q_, _$rootScope_) {
        $componentController = _$componentController_;
        $q = _$q_;
        $rootScope = _$rootScope_;

        ctrl = $componentController('renewLicense', {}, {});
    }));

    describe('initially', function() {
        beforeEach(function() {
            // We have to make angular resolve the promise (WhitelistService), since it is not done
            // automatically because no template is involved:
            // https://stackoverflow.com/questions/24211312/angular-q-when-is-not-resolved-in-karma-unit-test
            $rootScope.$apply();
        });

        it('controller should be defined', function() {
            expect(angular.isDefined(ctrl)).toBe(true);
        });
    });
});
