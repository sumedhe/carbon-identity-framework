/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.cors.mgt.core.test;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.database.utils.jdbc.NamedPreparedStatement;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.cors.mgt.core.CORSManagementService;
import org.wso2.carbon.identity.cors.mgt.core.constant.SchemaConstants.CORSOriginTableColumns;
import org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants;
import org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants.SampleApp1;
import org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants.SampleApp2;
import org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants.SampleTenant;
import org.wso2.carbon.identity.cors.mgt.core.dao.CORSConfigurationDAO;
import org.wso2.carbon.identity.cors.mgt.core.dao.CORSOriginDAO;
import org.wso2.carbon.identity.cors.mgt.core.dao.impl.CORSOriginDAOImpl;
import org.wso2.carbon.identity.cors.mgt.core.dao.impl.CacheBackedCORSConfigurationDAO;
import org.wso2.carbon.identity.cors.mgt.core.dao.impl.CacheBackedCORSOriginDAO;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceClientException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.internal.CORSManagementServiceHolder;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSConfigurationCache;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSConfigurationCacheEntry;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSConfigurationCacheKey;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSOriginByAppIdCache;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSOriginByAppIdCacheEntry;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSOriginByAppIdCacheKey;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSOriginCache;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSOriginCacheEntry;
import org.wso2.carbon.identity.cors.mgt.core.internal.cache.CORSOriginCacheKey;
import org.wso2.carbon.identity.cors.mgt.core.internal.impl.CORSManagementServiceImpl;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSApplication;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSOrigin;
import org.wso2.carbon.identity.cors.mgt.core.util.CarbonUtils;
import org.wso2.carbon.identity.cors.mgt.core.util.ConfigurationManagementUtils;
import org.wso2.carbon.identity.cors.mgt.core.util.DatabaseUtils;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManagerImpl;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.OrgResourceResolverService;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.exception.OrgResourceHierarchyTraverseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;
import static org.wso2.carbon.identity.cors.mgt.core.constant.ErrorMessages.ERROR_CODE_CORS_ADD;
import static org.wso2.carbon.identity.cors.mgt.core.constant.ErrorMessages.ERROR_CODE_CORS_RETRIEVE;
import static org.wso2.carbon.identity.cors.mgt.core.constant.SQLQueries.GET_CORS_ORIGINS_BY_APPLICATION_ID;
import static org.wso2.carbon.identity.cors.mgt.core.constant.SQLQueries.INSERT_CORS_ASSOCIATION;
import static org.wso2.carbon.identity.cors.mgt.core.constant.SQLQueries.INSERT_CORS_ORIGIN;
import static org.wso2.carbon.identity.cors.mgt.core.constant.SchemaConstants.CORSOriginTableColumns.ID;
import static org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants.INSERT_APPLICATION;
import static org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants.SAMPLE_CORS_ORIGIN_LIST_1;
import static org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants.SAMPLE_ORIGIN_LIST_1;
import static org.wso2.carbon.identity.cors.mgt.core.constant.TestConstants.SAMPLE_ORIGIN_LIST_2;
import static org.wso2.carbon.identity.cors.mgt.core.internal.util.ErrorUtils.handleServerException;

/**
 * Unit test cases for CORSService.
 */
public class CORSManagementServiceTests {

    private ConfigurationManager configurationManager;
    private Connection connection;
    private CORSManagementService corsManagementService;
    private CORSOriginDAO corsOriginDAO;

    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<ApplicationManagementService> applicationManagementService;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private OrganizationManager organizationManager;
    private OrgResourceResolverService orgResourceResolverService;

    @BeforeMethod
    public void setUp() throws Exception {

        DatabaseUtils.initiateH2Base();

        CarbonUtils.setCarbonHome();
        privilegedCarbonContext = mockStatic(PrivilegedCarbonContext.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        applicationManagementService = mockStatic(ApplicationManagementService.class);
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        orgResourceResolverService = mock(OrgResourceResolverService.class);

        CarbonUtils.mockCarbonContextForTenant(SUPER_TENANT_ID, SUPER_TENANT_DOMAIN_NAME, privilegedCarbonContext);
        CarbonUtils.mockIdentityTenantUtility(identityTenantUtil);
        CarbonUtils.mockRealmService();
        CarbonUtils.mockApplicationManagementService(applicationManagementService);

        connection = DatabaseUtils.createDataSource(identityDatabaseUtil);
        configurationManager = ConfigurationManagementUtils.getConfigurationManager();

        corsManagementService = new CORSManagementServiceImpl();
        CORSManagementServiceHolder.getInstance().setConfigurationManager(configurationManager);

        // Skip caches for testing.
        corsOriginDAO = new CORSOriginDAOImpl();
        CORSManagementServiceHolder.getInstance().setCorsOriginDAO(corsOriginDAO);

        organizationManager = new OrganizationManagerImpl();
        CORSManagementServiceHolder.getInstance().setOrganizationManager(organizationManager);

        CORSManagementServiceHolder.getInstance().setOrgResourceResolverService(orgResourceResolverService);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        connection.close();
        DatabaseUtils.closeH2Base();
        privilegedCarbonContext.close();
        identityTenantUtil.close();
        applicationManagementService.close();
        identityDatabaseUtil.close();
    }

    @Test
    public void testGetCORSOriginsWithNonExisting()
            throws CORSManagementServiceException, OrgResourceHierarchyTraverseException {

        when(orgResourceResolverService.getResourcesFromOrgHierarchy(anyString(), any(), any()))
                .thenReturn(new ArrayList<CORSOrigin>());
        List<CORSOrigin> corsOrigins = corsManagementService.getTenantCORSOrigins(SUPER_TENANT_DOMAIN_NAME);

        assertTrue(corsOrigins.isEmpty());
    }

    @Test
    public void testGetCORSOriginsWithSuperTenant()
            throws CORSManagementServiceException, OrgResourceHierarchyTraverseException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            for (String origin : SAMPLE_ORIGIN_LIST_1) {
                // Origin is not present. Therefore add an origin and set the tenant association.
                try (NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                        INSERT_CORS_ORIGIN)) {
                    namedPreparedStatement.setInt(1, SUPER_TENANT_ID);
                    namedPreparedStatement.setString(2, origin);
                    namedPreparedStatement.setString(3, UUID.randomUUID().toString());
                    namedPreparedStatement.executeUpdate();
                }
            }
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw handleServerException(ERROR_CODE_CORS_ADD, e, IdentityTenantUtil.getTenantDomain(SUPER_TENANT_ID));
        }

        when(orgResourceResolverService.getResourcesFromOrgHierarchy(anyString(), any(), any()))
                .thenReturn(SAMPLE_CORS_ORIGIN_LIST_1);
        List<String> retrievedOrigins = corsManagementService.getTenantCORSOrigins(SUPER_TENANT_DOMAIN_NAME)
                .stream().map(CORSOrigin::getOrigin).collect(Collectors.toList());

        assertEquals(retrievedOrigins, SAMPLE_ORIGIN_LIST_1);
    }

    @Test
    public void testGetCORSOriginsWithApplication() throws CORSManagementServiceException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                for (String origin : SAMPLE_ORIGIN_LIST_1) {
                    try (NamedPreparedStatement namedPreparedStatement =
                                 new NamedPreparedStatement(connection, INSERT_CORS_ORIGIN, ID)) {
                        // Origin is not present. Therefore add an origin.
                        namedPreparedStatement.setInt(1, SampleTenant.ID);
                        namedPreparedStatement.setString(2, origin);
                        namedPreparedStatement.setString(3, UUID.randomUUID().toString());
                        namedPreparedStatement.executeUpdate();

                        // Get origin id.
                        int corsOriginId;
                        try (ResultSet resultSet = namedPreparedStatement.getGeneratedKeys()) {
                            if (resultSet.next()) {
                                corsOriginId = resultSet.getInt(1);
                            } else {
                                IdentityDatabaseUtil.rollbackTransaction(connection);
                                throw handleServerException(ERROR_CODE_CORS_ADD, SampleTenant.DOMAIN_NAME);
                            }
                        }

                        try (PreparedStatement preparedStatement3 =
                                     connection.prepareStatement(INSERT_CORS_ASSOCIATION)) {
                            // Add application associations.
                            preparedStatement3.setInt(1, corsOriginId);
                            preparedStatement3.setInt(2, SampleApp1.ID);
                            preparedStatement3.executeUpdate();
                        }
                    }
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw handleServerException(ERROR_CODE_CORS_ADD, e,
                        IdentityTenantUtil.getTenantDomain(SampleTenant.ID));
            }
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw handleServerException(ERROR_CODE_CORS_ADD, e, SampleTenant.DOMAIN_NAME);
        }

        List<String> retrievedOrigins = corsManagementService.getApplicationCORSOrigins(
                SampleApp1.UUID,
                SampleTenant.DOMAIN_NAME).stream().map(CORSOrigin::getOrigin).collect(Collectors.toList());

        assertEquals(retrievedOrigins, SAMPLE_ORIGIN_LIST_1);
    }

    @Test
    public void testSetCORSOrigins() throws CORSManagementServiceException {

        corsManagementService.setCORSOrigins(SampleApp1.UUID, SAMPLE_ORIGIN_LIST_1, SUPER_TENANT_DOMAIN_NAME);
        corsManagementService.setCORSOrigins(SampleApp2.UUID, SAMPLE_ORIGIN_LIST_2, SUPER_TENANT_DOMAIN_NAME);

        List<CORSOrigin> retrievedCORSOrigins = new ArrayList<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (NamedPreparedStatement namedPreparedStatement =
                         new NamedPreparedStatement(connection, GET_CORS_ORIGINS_BY_APPLICATION_ID)) {
                namedPreparedStatement.setInt(1, SUPER_TENANT_ID);
                namedPreparedStatement.setInt(2, SampleApp1.ID);
                try (ResultSet resultSet = namedPreparedStatement.executeQuery()) {
                    while (resultSet.next()) {
                        CORSOrigin corsOrigin = new CORSOrigin();
                        corsOrigin.setId(resultSet.getString(CORSOriginTableColumns.ID));
                        corsOrigin.setOrigin(resultSet.getString(CORSOriginTableColumns.ORIGIN));
                        retrievedCORSOrigins.add(corsOrigin);
                    }
                }
            }
        } catch (SQLException e) {
            throw handleServerException(ERROR_CODE_CORS_RETRIEVE, e, SUPER_TENANT_DOMAIN_NAME);
        }

        assertEquals(retrievedCORSOrigins.stream().map(CORSOrigin::getOrigin).collect(Collectors.toList()),
                SAMPLE_ORIGIN_LIST_1);
    }

    @Test
    public void testAddCORSOrigins() throws CORSManagementServiceException {

        corsManagementService.addCORSOrigins(SampleApp1.UUID, SAMPLE_ORIGIN_LIST_1, SUPER_TENANT_DOMAIN_NAME);

        List<CORSOrigin> retrievedCORSOrigins = new ArrayList<>();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (NamedPreparedStatement namedPreparedStatement =
                         new NamedPreparedStatement(connection, GET_CORS_ORIGINS_BY_APPLICATION_ID)) {
                namedPreparedStatement.setInt(1, SUPER_TENANT_ID);
                namedPreparedStatement.setInt(2, SampleApp1.ID);
                try (ResultSet resultSet = namedPreparedStatement.executeQuery()) {
                    while (resultSet.next()) {
                        CORSOrigin corsOrigin = new CORSOrigin();
                        corsOrigin.setId(resultSet.getString(CORSOriginTableColumns.ID));
                        corsOrigin.setOrigin(resultSet.getString(CORSOriginTableColumns.ORIGIN));
                        retrievedCORSOrigins.add(corsOrigin);
                    }
                }
            }
        } catch (SQLException e) {
            throw handleServerException(ERROR_CODE_CORS_RETRIEVE, e, SUPER_TENANT_DOMAIN_NAME);
        }

        assertEquals(retrievedCORSOrigins.stream().map(CORSOrigin::getOrigin).collect(Collectors.toList()),
                SAMPLE_ORIGIN_LIST_1);
    }

    @Test
    public void testAddCORSOriginsWithInvalidApp() {

        assertThrows(CORSManagementServiceClientException.class, () -> corsManagementService
                .addCORSOrigins(TestConstants.SampleApp3.UUID, SAMPLE_ORIGIN_LIST_2, SUPER_TENANT_DOMAIN_NAME));
    }

    @Test
    public void testDeleteApplicationCORSOrigins() throws CORSManagementServiceException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                for (String origin : SAMPLE_ORIGIN_LIST_1) {
                    // Origin is not present. Therefore add the origin.
                    try (NamedPreparedStatement namedPreparedStatement =
                                 new NamedPreparedStatement(connection, INSERT_CORS_ORIGIN, ID)) {
                        namedPreparedStatement.setInt(1, SUPER_TENANT_ID);
                        namedPreparedStatement.setString(2, origin);
                        namedPreparedStatement.setString(3, UUID.randomUUID().toString());
                        namedPreparedStatement.executeUpdate();

                        // Get origin id.
                        int corsOriginId = -1;
                        try (ResultSet resultSet1 = namedPreparedStatement.getGeneratedKeys()) {
                            if (resultSet1.next()) {
                                corsOriginId = resultSet1.getInt(1);
                            } else {
                                IdentityDatabaseUtil.rollbackTransaction(connection);
                                throw handleServerException(ERROR_CODE_CORS_ADD, IdentityTenantUtil.getTenantDomain(
                                        SUPER_TENANT_ID));
                            }
                        }

                        try (PreparedStatement preparedStatement2 =
                                     connection.prepareStatement(INSERT_CORS_ASSOCIATION)) {
                            // Add application associations.
                            preparedStatement2.setInt(1, corsOriginId);
                            preparedStatement2.setInt(2, SampleApp1.ID);
                            preparedStatement2.executeUpdate();
                        }
                    }
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw handleServerException(ERROR_CODE_CORS_ADD, e, SampleTenant.DOMAIN_NAME);
            }

            // Commit the transaction as no errors were thrown.
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw handleServerException(ERROR_CODE_CORS_ADD, e, SampleTenant.DOMAIN_NAME);
        }

        List<CORSOrigin> preRetrievedOrigins = corsManagementService
                .getApplicationCORSOrigins(SampleApp1.UUID, SUPER_TENANT_DOMAIN_NAME);

        corsManagementService.deleteCORSOrigins(SampleApp1.UUID, preRetrievedOrigins.subList(0, 2)
                .stream().map(CORSOrigin::getId).collect(Collectors.toList()), SUPER_TENANT_DOMAIN_NAME);

        List<CORSOrigin> retrievedOrigins = corsManagementService
                .getApplicationCORSOrigins(SampleApp1.UUID, SUPER_TENANT_DOMAIN_NAME);

        assertEquals(retrievedOrigins.stream().map(CORSOrigin::getOrigin).collect(Collectors.toList()),
                SAMPLE_ORIGIN_LIST_1.subList(2, SAMPLE_ORIGIN_LIST_1.size()));
    }

    @Test
    public void testGetCORSApplicationsByCORSOriginId() throws CORSManagementServiceException {

        String originUUID = UUID.randomUUID().toString();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                // Add the application.
                try (PreparedStatement preparedStatement1 = connection.prepareStatement(INSERT_APPLICATION)) {
                    // Add application 1.
                    preparedStatement1.setInt(1, SampleApp1.ID);
                    preparedStatement1.setInt(2, SampleTenant.ID);
                    preparedStatement1.setString(3, SampleApp1.NAME);
                    preparedStatement1.setString(4, SampleApp1.UUID);
                    preparedStatement1.executeUpdate();
                }

                // Add the application.
                try (PreparedStatement preparedStatement2 = connection.prepareStatement(INSERT_APPLICATION)) {
                    // Add application 2.
                    preparedStatement2.setInt(1, SampleApp2.ID);
                    preparedStatement2.setInt(2, SampleApp2.ID);
                    preparedStatement2.setString(3, SampleApp2.NAME);
                    preparedStatement2.setString(4, SampleApp2.UUID);
                    preparedStatement2.executeUpdate();
                }

                String origin = SAMPLE_ORIGIN_LIST_1.get(0);
                try (NamedPreparedStatement namedPreparedStatement =
                             new NamedPreparedStatement(connection, INSERT_CORS_ORIGIN, ID)) {
                    // Origin is not present. Therefore add an origin.
                    namedPreparedStatement.setInt(1, SampleTenant.ID);
                    namedPreparedStatement.setString(2, origin);
                    namedPreparedStatement.setString(3, originUUID);
                    namedPreparedStatement.executeUpdate();

                    // Get origin id.
                    int corsOriginId;
                    try (ResultSet resultSet = namedPreparedStatement.getGeneratedKeys()) {
                        if (resultSet.next()) {
                            corsOriginId = resultSet.getInt(1);
                        } else {
                            IdentityDatabaseUtil.rollbackTransaction(connection);
                            throw handleServerException(ERROR_CODE_CORS_ADD, SampleTenant.DOMAIN_NAME);
                        }
                    }

                    try (PreparedStatement preparedStatement4 =
                                 connection.prepareStatement(INSERT_CORS_ASSOCIATION)) {
                        // Add application associations.
                        preparedStatement4.setInt(1, corsOriginId);
                        preparedStatement4.setInt(2, SampleApp1.ID);
                        preparedStatement4.executeUpdate();
                    }

                    try (PreparedStatement preparedStatement5 =
                                 connection.prepareStatement(INSERT_CORS_ASSOCIATION)) {
                        // Add application associations.
                        preparedStatement5.setInt(1, corsOriginId);
                        preparedStatement5.setInt(2, SampleApp2.ID);
                        preparedStatement5.executeUpdate();
                    }
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw handleServerException(ERROR_CODE_CORS_ADD, e,
                        IdentityTenantUtil.getTenantDomain(SampleTenant.ID));
            }
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw handleServerException(ERROR_CODE_CORS_ADD, e, SampleTenant.DOMAIN_NAME);
        }

        List<String> retrievedCORSOriginApplicationIds = corsManagementService.getCORSApplicationsByCORSOriginId(
                originUUID,
                SampleTenant.DOMAIN_NAME).stream().map(CORSApplication::getId).collect(Collectors.toList());

        List<String> expectedApplicationIds = new ArrayList<>();
        expectedApplicationIds.add(SampleApp1.UUID);
        expectedApplicationIds.add(SampleApp2.UUID);
        assertEquals(retrievedCORSOriginApplicationIds, expectedApplicationIds);
    }

    @Test
    public void testGetCORSConfigurationByTenantDomainCacheMissUsesAddToCacheOnRead()
            throws CORSManagementServiceException {

        CORSConfigurationDAO corsConfigurationDAO = mock(CORSConfigurationDAO.class);
        CORSConfiguration cachedConfiguration = new CORSConfiguration();
        when(corsConfigurationDAO.getCORSConfigurationByTenantDomain(SampleTenant.DOMAIN_NAME))
                .thenReturn(cachedConfiguration);

        CORSConfigurationCache corsConfigurationCache = mock(CORSConfigurationCache.class);
        when(corsConfigurationCache.getValueFromCache(any(CORSConfigurationCacheKey.class), anyString()))
                .thenReturn(null);

        try (MockedStatic<CORSConfigurationCache> corsConfigurationCacheMockedStatic =
                     mockStatic(CORSConfigurationCache.class)) {
            corsConfigurationCacheMockedStatic.when(CORSConfigurationCache::getInstance)
                    .thenReturn(corsConfigurationCache);

            CacheBackedCORSConfigurationDAO cacheBackedCORSConfigurationDAO =
                    new CacheBackedCORSConfigurationDAO(corsConfigurationDAO);
            CORSConfiguration retrievedConfiguration = cacheBackedCORSConfigurationDAO
                    .getCORSConfigurationByTenantDomain(SampleTenant.DOMAIN_NAME);

            assertEquals(retrievedConfiguration, cachedConfiguration);
            verify(corsConfigurationDAO).getCORSConfigurationByTenantDomain(SampleTenant.DOMAIN_NAME);
            verify(corsConfigurationCache).addToCacheOnRead(any(CORSConfigurationCacheKey.class),
                    any(CORSConfigurationCacheEntry.class));
            verify(corsConfigurationCache, never()).addToCache(any(CORSConfigurationCacheKey.class),
                    any(CORSConfigurationCacheEntry.class), anyString());
        }
    }

    @Test
    public void testGetCORSOriginsByTenantIdCacheMissUsesAddToCacheOnRead()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        when(mockCorsOriginDAO.getCORSOriginsByTenantId(SampleTenant.ID)).thenReturn(SAMPLE_CORS_ORIGIN_LIST_1);

        CORSOriginCache corsOriginCache = mock(CORSOriginCache.class);
        when(corsOriginCache.getValueFromCache(any(CORSOriginCacheKey.class), anyInt())).thenReturn(null);

        try (MockedStatic<CORSOriginCache> corsOriginCacheMockedStatic = mockStatic(CORSOriginCache.class)) {
            corsOriginCacheMockedStatic.when(CORSOriginCache::getInstance).thenReturn(corsOriginCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            List<CORSOrigin> retrievedOrigins = cacheBackedCORSOriginDAO.getCORSOriginsByTenantId(SampleTenant.ID);

            assertEquals(retrievedOrigins, SAMPLE_CORS_ORIGIN_LIST_1);
            verify(mockCorsOriginDAO).getCORSOriginsByTenantId(SampleTenant.ID);
            verify(corsOriginCache).addToCacheOnRead(any(CORSOriginCacheKey.class), any(CORSOriginCacheEntry.class));
            verify(corsOriginCache, never()).addToCache(any(CORSOriginCacheKey.class),
                    any(CORSOriginCacheEntry.class), anyInt());
        }
    }

    @Test
    public void testGetCORSOriginsByApplicationIdCacheMissUsesAddToCacheOnRead()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        when(mockCorsOriginDAO.getCORSOriginsByApplicationId(SampleApp1.ID, SampleTenant.ID))
                .thenReturn(SAMPLE_CORS_ORIGIN_LIST_1);

        CORSOriginByAppIdCache corsOriginByAppIdCache = mock(CORSOriginByAppIdCache.class);
        when(corsOriginByAppIdCache.getValueFromCache(any(CORSOriginByAppIdCacheKey.class), anyInt()))
                .thenReturn(null);

        try (MockedStatic<CORSOriginByAppIdCache> corsOriginByAppIdCacheMockedStatic =
                     mockStatic(CORSOriginByAppIdCache.class)) {
            corsOriginByAppIdCacheMockedStatic.when(CORSOriginByAppIdCache::getInstance)
                    .thenReturn(corsOriginByAppIdCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            List<CORSOrigin> retrievedOrigins = cacheBackedCORSOriginDAO
                    .getCORSOriginsByApplicationId(SampleApp1.ID, SampleTenant.ID);

            assertEquals(retrievedOrigins, SAMPLE_CORS_ORIGIN_LIST_1);
            verify(mockCorsOriginDAO).getCORSOriginsByApplicationId(SampleApp1.ID, SampleTenant.ID);
            verify(corsOriginByAppIdCache).addToCacheOnRead(any(CORSOriginByAppIdCacheKey.class),
                    any(CORSOriginByAppIdCacheEntry.class));
            verify(corsOriginByAppIdCache, never()).addToCache(any(CORSOriginByAppIdCacheKey.class),
                    any(CORSOriginByAppIdCacheEntry.class), anyInt());
        }
    }

    @Test
    public void testGetCORSConfigurationByTenantDomainNullCachedPayloadUsesAddToCacheOnRead()
            throws CORSManagementServiceException {

        CORSConfigurationDAO corsConfigurationDAO = mock(CORSConfigurationDAO.class);
        CORSConfiguration dbConfiguration = new CORSConfiguration();
        when(corsConfigurationDAO.getCORSConfigurationByTenantDomain(SampleTenant.DOMAIN_NAME))
                .thenReturn(dbConfiguration);

        CORSConfigurationCache corsConfigurationCache = mock(CORSConfigurationCache.class);
        when(corsConfigurationCache.getValueFromCache(any(CORSConfigurationCacheKey.class), anyString()))
                .thenReturn(new CORSConfigurationCacheEntry(null));

        try (MockedStatic<CORSConfigurationCache> corsConfigurationCacheMockedStatic =
                     mockStatic(CORSConfigurationCache.class)) {
            corsConfigurationCacheMockedStatic.when(CORSConfigurationCache::getInstance)
                    .thenReturn(corsConfigurationCache);

            CacheBackedCORSConfigurationDAO cacheBackedCORSConfigurationDAO =
                    new CacheBackedCORSConfigurationDAO(corsConfigurationDAO);
            CORSConfiguration retrievedConfiguration = cacheBackedCORSConfigurationDAO
                    .getCORSConfigurationByTenantDomain(SampleTenant.DOMAIN_NAME);

            assertEquals(retrievedConfiguration, dbConfiguration);
            verify(corsConfigurationDAO).getCORSConfigurationByTenantDomain(SampleTenant.DOMAIN_NAME);
            verify(corsConfigurationCache).addToCacheOnRead(any(CORSConfigurationCacheKey.class),
                    any(CORSConfigurationCacheEntry.class));
            verify(corsConfigurationCache, never()).addToCache(any(CORSConfigurationCacheKey.class),
                    any(CORSConfigurationCacheEntry.class), anyString());
        }
    }

    @Test
    public void testGetCORSOriginsByTenantIdNullCachedPayloadUsesAddToCacheOnRead()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        when(mockCorsOriginDAO.getCORSOriginsByTenantId(SampleTenant.ID)).thenReturn(SAMPLE_CORS_ORIGIN_LIST_1);

        CORSOriginCache corsOriginCache = mock(CORSOriginCache.class);
        when(corsOriginCache.getValueFromCache(any(CORSOriginCacheKey.class), anyInt()))
                .thenReturn(new CORSOriginCacheEntry(null));

        try (MockedStatic<CORSOriginCache> corsOriginCacheMockedStatic = mockStatic(CORSOriginCache.class)) {
            corsOriginCacheMockedStatic.when(CORSOriginCache::getInstance).thenReturn(corsOriginCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            List<CORSOrigin> retrievedOrigins = cacheBackedCORSOriginDAO.getCORSOriginsByTenantId(SampleTenant.ID);

            assertEquals(retrievedOrigins, SAMPLE_CORS_ORIGIN_LIST_1);
            verify(mockCorsOriginDAO).getCORSOriginsByTenantId(SampleTenant.ID);
            verify(corsOriginCache).addToCacheOnRead(any(CORSOriginCacheKey.class), any(CORSOriginCacheEntry.class));
            verify(corsOriginCache, never()).addToCache(any(CORSOriginCacheKey.class),
                    any(CORSOriginCacheEntry.class), anyInt());
        }
    }

    @Test
    public void testGetCORSOriginsByApplicationIdNullCachedPayloadUsesAddToCacheOnRead()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        when(mockCorsOriginDAO.getCORSOriginsByApplicationId(SampleApp1.ID, SampleTenant.ID))
                .thenReturn(SAMPLE_CORS_ORIGIN_LIST_1);

        CORSOriginByAppIdCache corsOriginByAppIdCache = mock(CORSOriginByAppIdCache.class);
        when(corsOriginByAppIdCache.getValueFromCache(any(CORSOriginByAppIdCacheKey.class), anyInt()))
                .thenReturn(new CORSOriginByAppIdCacheEntry(null));

        try (MockedStatic<CORSOriginByAppIdCache> corsOriginByAppIdCacheMockedStatic =
                     mockStatic(CORSOriginByAppIdCache.class)) {
            corsOriginByAppIdCacheMockedStatic.when(CORSOriginByAppIdCache::getInstance)
                    .thenReturn(corsOriginByAppIdCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            List<CORSOrigin> retrievedOrigins = cacheBackedCORSOriginDAO
                    .getCORSOriginsByApplicationId(SampleApp1.ID, SampleTenant.ID);

            assertEquals(retrievedOrigins, SAMPLE_CORS_ORIGIN_LIST_1);
            verify(mockCorsOriginDAO).getCORSOriginsByApplicationId(SampleApp1.ID, SampleTenant.ID);
            verify(corsOriginByAppIdCache).addToCacheOnRead(any(CORSOriginByAppIdCacheKey.class),
                    any(CORSOriginByAppIdCacheEntry.class));
            verify(corsOriginByAppIdCache, never()).addToCache(any(CORSOriginByAppIdCacheKey.class),
                    any(CORSOriginByAppIdCacheEntry.class), anyInt());
        }
    }

    @Test
    public void testGetCORSConfigurationByTenantDomainCacheHitSkipsDAOAndReadCachePopulation()
            throws CORSManagementServiceException {

        CORSConfigurationDAO corsConfigurationDAO = mock(CORSConfigurationDAO.class);
        CORSConfiguration cachedConfiguration = new CORSConfiguration();
        CORSConfigurationCacheEntry cacheEntry = new CORSConfigurationCacheEntry(cachedConfiguration);

        CORSConfigurationCache corsConfigurationCache = mock(CORSConfigurationCache.class);
        when(corsConfigurationCache.getValueFromCache(any(CORSConfigurationCacheKey.class), anyString()))
                .thenReturn(cacheEntry);

        try (MockedStatic<CORSConfigurationCache> corsConfigurationCacheMockedStatic =
                     mockStatic(CORSConfigurationCache.class)) {
            corsConfigurationCacheMockedStatic.when(CORSConfigurationCache::getInstance)
                    .thenReturn(corsConfigurationCache);

            CacheBackedCORSConfigurationDAO cacheBackedCORSConfigurationDAO =
                    new CacheBackedCORSConfigurationDAO(corsConfigurationDAO);
            CORSConfiguration retrievedConfiguration = cacheBackedCORSConfigurationDAO
                    .getCORSConfigurationByTenantDomain(SampleTenant.DOMAIN_NAME);

            assertEquals(retrievedConfiguration, cachedConfiguration);
            verify(corsConfigurationDAO, never()).getCORSConfigurationByTenantDomain(anyString());
            verify(corsConfigurationCache, never()).addToCacheOnRead(any(CORSConfigurationCacheKey.class),
                    any(CORSConfigurationCacheEntry.class));
        }
    }

    @Test
    public void testGetCORSOriginsByTenantIdCacheHitSkipsDAOAndReadCachePopulation()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        CORSOriginCacheEntry cacheEntry = new CORSOriginCacheEntry(
                SAMPLE_CORS_ORIGIN_LIST_1.toArray(new CORSOrigin[0]));

        CORSOriginCache corsOriginCache = mock(CORSOriginCache.class);
        when(corsOriginCache.getValueFromCache(any(CORSOriginCacheKey.class), anyInt())).thenReturn(cacheEntry);

        try (MockedStatic<CORSOriginCache> corsOriginCacheMockedStatic = mockStatic(CORSOriginCache.class)) {
            corsOriginCacheMockedStatic.when(CORSOriginCache::getInstance).thenReturn(corsOriginCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            List<CORSOrigin> retrievedOrigins = cacheBackedCORSOriginDAO.getCORSOriginsByTenantId(SampleTenant.ID);

            assertEquals(retrievedOrigins, SAMPLE_CORS_ORIGIN_LIST_1);
            verify(mockCorsOriginDAO, never()).getCORSOriginsByTenantId(anyInt());
            verify(corsOriginCache, never()).addToCacheOnRead(any(CORSOriginCacheKey.class),
                    any(CORSOriginCacheEntry.class));
        }
    }

    @Test
    public void testGetCORSOriginsByApplicationIdCacheHitSkipsDAOAndReadCachePopulation()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        CORSOriginByAppIdCacheEntry cacheEntry =
                new CORSOriginByAppIdCacheEntry(SAMPLE_CORS_ORIGIN_LIST_1.toArray(new CORSOrigin[0]));

        CORSOriginByAppIdCache corsOriginByAppIdCache = mock(CORSOriginByAppIdCache.class);
        when(corsOriginByAppIdCache.getValueFromCache(any(CORSOriginByAppIdCacheKey.class), anyInt()))
                .thenReturn(cacheEntry);

        try (MockedStatic<CORSOriginByAppIdCache> corsOriginByAppIdCacheMockedStatic =
                     mockStatic(CORSOriginByAppIdCache.class)) {
            corsOriginByAppIdCacheMockedStatic.when(CORSOriginByAppIdCache::getInstance)
                    .thenReturn(corsOriginByAppIdCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            List<CORSOrigin> retrievedOrigins = cacheBackedCORSOriginDAO
                    .getCORSOriginsByApplicationId(SampleApp1.ID, SampleTenant.ID);

            assertEquals(retrievedOrigins, SAMPLE_CORS_ORIGIN_LIST_1);
            verify(mockCorsOriginDAO, never()).getCORSOriginsByApplicationId(anyInt(), anyInt());
            verify(corsOriginByAppIdCache, never()).addToCacheOnRead(any(CORSOriginByAppIdCacheKey.class),
                    any(CORSOriginByAppIdCacheEntry.class));
        }
    }

    @Test
    public void testSetCORSConfigurationByTenantDomainClearsCacheAndDelegates()
            throws CORSManagementServiceException {

        CORSConfigurationDAO corsConfigurationDAO = mock(CORSConfigurationDAO.class);
        CORSConfiguration corsConfiguration = new CORSConfiguration();
        CORSConfigurationCache corsConfigurationCache = mock(CORSConfigurationCache.class);

        try (MockedStatic<CORSConfigurationCache> corsConfigurationCacheMockedStatic =
                     mockStatic(CORSConfigurationCache.class)) {
            corsConfigurationCacheMockedStatic.when(CORSConfigurationCache::getInstance)
                    .thenReturn(corsConfigurationCache);

            CacheBackedCORSConfigurationDAO cacheBackedCORSConfigurationDAO =
                    new CacheBackedCORSConfigurationDAO(corsConfigurationDAO);
            cacheBackedCORSConfigurationDAO.setCORSConfigurationByTenantDomain(corsConfiguration,
                    SampleTenant.DOMAIN_NAME);

            verify(corsConfigurationCache).clearCacheEntry(any(CORSConfigurationCacheKey.class),
                    eq(SampleTenant.DOMAIN_NAME));
            verify(corsConfigurationDAO).setCORSConfigurationByTenantDomain(corsConfiguration,
                    SampleTenant.DOMAIN_NAME);
        }
    }

    @Test
    public void testSetCORSOriginsClearsBothCachesAndDelegates()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        CORSOriginByAppIdCache corsOriginByAppIdCache = mock(CORSOriginByAppIdCache.class);
        CORSOriginCache corsOriginCache = mock(CORSOriginCache.class);

        try (MockedStatic<CORSOriginByAppIdCache> corsOriginByAppIdCacheMockedStatic =
                     mockStatic(CORSOriginByAppIdCache.class);
             MockedStatic<CORSOriginCache> corsOriginCacheMockedStatic = mockStatic(CORSOriginCache.class)) {
            corsOriginByAppIdCacheMockedStatic.when(CORSOriginByAppIdCache::getInstance)
                    .thenReturn(corsOriginByAppIdCache);
            corsOriginCacheMockedStatic.when(CORSOriginCache::getInstance).thenReturn(corsOriginCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            cacheBackedCORSOriginDAO.setCORSOrigins(SampleApp1.ID, SAMPLE_CORS_ORIGIN_LIST_1, SampleTenant.ID);

            verify(corsOriginByAppIdCache).clearCacheEntry(any(CORSOriginByAppIdCacheKey.class), eq(SampleTenant.ID));
            verify(corsOriginCache).clearCacheEntry(any(CORSOriginCacheKey.class), eq(SampleTenant.ID));
            verify(mockCorsOriginDAO).setCORSOrigins(SampleApp1.ID, SAMPLE_CORS_ORIGIN_LIST_1, SampleTenant.ID);
        }
    }

    @Test
    public void testAddCORSOriginsClearsBothCachesAndDelegates()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        CORSOriginByAppIdCache corsOriginByAppIdCache = mock(CORSOriginByAppIdCache.class);
        CORSOriginCache corsOriginCache = mock(CORSOriginCache.class);

        try (MockedStatic<CORSOriginByAppIdCache> corsOriginByAppIdCacheMockedStatic =
                     mockStatic(CORSOriginByAppIdCache.class);
             MockedStatic<CORSOriginCache> corsOriginCacheMockedStatic = mockStatic(CORSOriginCache.class)) {
            corsOriginByAppIdCacheMockedStatic.when(CORSOriginByAppIdCache::getInstance)
                    .thenReturn(corsOriginByAppIdCache);
            corsOriginCacheMockedStatic.when(CORSOriginCache::getInstance).thenReturn(corsOriginCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            cacheBackedCORSOriginDAO.addCORSOrigins(SampleApp1.ID, SAMPLE_CORS_ORIGIN_LIST_1, SampleTenant.ID);

            verify(corsOriginByAppIdCache).clearCacheEntry(any(CORSOriginByAppIdCacheKey.class), eq(SampleTenant.ID));
            verify(corsOriginCache).clearCacheEntry(any(CORSOriginCacheKey.class), eq(SampleTenant.ID));
            verify(mockCorsOriginDAO).addCORSOrigins(SampleApp1.ID, SAMPLE_CORS_ORIGIN_LIST_1, SampleTenant.ID);
        }
    }

    @Test
    public void testDeleteCORSOriginsClearsBothCachesAndDelegates()
            throws CORSManagementServiceException {

        CORSOriginDAO mockCorsOriginDAO = mock(CORSOriginDAO.class);
        CORSOriginByAppIdCache corsOriginByAppIdCache = mock(CORSOriginByAppIdCache.class);
        CORSOriginCache corsOriginCache = mock(CORSOriginCache.class);
        List<String> originIdsToDelete = SAMPLE_CORS_ORIGIN_LIST_1.stream().map(CORSOrigin::getId)
                .collect(Collectors.toList());

        try (MockedStatic<CORSOriginByAppIdCache> corsOriginByAppIdCacheMockedStatic =
                     mockStatic(CORSOriginByAppIdCache.class);
             MockedStatic<CORSOriginCache> corsOriginCacheMockedStatic = mockStatic(CORSOriginCache.class)) {
            corsOriginByAppIdCacheMockedStatic.when(CORSOriginByAppIdCache::getInstance)
                    .thenReturn(corsOriginByAppIdCache);
            corsOriginCacheMockedStatic.when(CORSOriginCache::getInstance).thenReturn(corsOriginCache);

            CacheBackedCORSOriginDAO cacheBackedCORSOriginDAO = new CacheBackedCORSOriginDAO(mockCorsOriginDAO);
            cacheBackedCORSOriginDAO.deleteCORSOrigins(SampleApp1.ID, originIdsToDelete, SampleTenant.ID);

            verify(corsOriginByAppIdCache).clearCacheEntry(any(CORSOriginByAppIdCacheKey.class), eq(SampleTenant.ID));
            verify(corsOriginCache).clearCacheEntry(any(CORSOriginCacheKey.class), eq(SampleTenant.ID));
            verify(mockCorsOriginDAO).deleteCORSOrigins(SampleApp1.ID, originIdsToDelete, SampleTenant.ID);
        }
    }
}
