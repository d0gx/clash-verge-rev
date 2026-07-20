import {
  Box,
  Button,
  List,
  ListItem,
  ListItemText,
  MenuItem,
  TextField,
  Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import type { Ref } from 'react'
import { useImperativeHandle, useState } from 'react'
import { useTranslation } from 'react-i18next'

import {
  BaseDialog,
  BaseSplitChipEditor,
  TooltipIcon,
  DialogRef,
  Switch,
} from '@/components/base'
import { useClash } from '@/hooks/use-clash'
import { useVerge } from '@/hooks/use-verge'
import {
  enhanceProfiles,
  listWindowsIcsConnections,
  patchWindowsTunAndIcsConfig,
  repairWindowsIcs,
} from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import getSystem from '@/utils/get-system'
import { areValidIpCidrs } from '@/utils/network'

import { StackModeSwitch } from './stack-mode-switch'

const OS = getSystem()

const splitRouteExcludeAddress = (value: string) =>
  value
    .split(/[,\n;\r]+/)
    .map((item) => item.trim())
    .filter(Boolean)

export function TunViewer({ ref }: { ref?: Ref<DialogRef> }) {
  const { t } = useTranslation()

  const { clash, mutateClash, patchClash } = useClash()
  const { verge, mutateVerge } = useVerge()

  const [open, setOpen] = useState(false)
  const [icsConnections, setIcsConnections] = useState<WindowsIcsConnection[]>(
    [],
  )
  const [icsConnectionsLoading, setIcsConnectionsLoading] = useState(false)
  const [icsRepairing, setIcsRepairing] = useState(false)
  const [icsAutoRecovery, setIcsAutoRecovery] = useState(false)
  const [icsPrivateGuid, setIcsPrivateGuid] = useState('')
  const [icsPrivateName, setIcsPrivateName] = useState('')
  const [values, setValues] = useState({
    stack: 'mixed',
    device: OS === 'macos' ? 'utun1024' : 'Mihomo',
    autoRoute: true,
    routeExcludeAddress: '',
    autoRedirect: false,
    autoDetectInterface: true,
    dnsHijack: ['any:53'],
    strictRoute: false,
    mtu: 1500,
  })

  const routeExcludeAddressItems = splitRouteExcludeAddress(
    values.routeExcludeAddress,
  )
  const routeExcludeAddressError =
    values.autoRoute &&
    routeExcludeAddressItems.length > 0 &&
    !areValidIpCidrs(routeExcludeAddressItems)
  const routeExcludeAddressHelperText = routeExcludeAddressError
    ? t('settings.modals.tun.messages.invalidRouteExcludeAddress')
    : t('settings.modals.tun.messages.routeExcludeAddressHint')

  const loadIcsConnections = useLockFn(async () => {
    if (OS !== 'windows') return
    setIcsConnectionsLoading(true)
    try {
      setIcsConnections(await listWindowsIcsConnections())
    } catch (err: any) {
      showNotice.error(err)
    } finally {
      setIcsConnectionsLoading(false)
    }
  })

  useImperativeHandle(ref, () => ({
    open: () => {
      setOpen(true)
      const nextAutoRoute = clash?.tun['auto-route'] ?? true
      const rawAutoRedirect = clash?.tun['auto-redirect'] ?? false
      const computedAutoRedirect =
        OS === 'linux' ? (nextAutoRoute ? rawAutoRedirect : false) : false
      setValues({
        stack: clash?.tun.stack ?? 'gvisor',
        device: clash?.tun.device ?? (OS === 'macos' ? 'utun1024' : 'Mihomo'),
        autoRoute: nextAutoRoute,
        routeExcludeAddress: (clash?.tun['route-exclude-address'] ?? []).join(
          ',',
        ),
        autoRedirect: computedAutoRedirect,
        autoDetectInterface: clash?.tun['auto-detect-interface'] ?? true,
        dnsHijack: clash?.tun['dns-hijack'] ?? ['any:53'],
        strictRoute: clash?.tun['strict-route'] ?? false,
        mtu: clash?.tun.mtu ?? 1500,
      })
      if (OS === 'windows') {
        setIcsAutoRecovery(verge?.enable_windows_ics_recovery ?? false)
        setIcsPrivateGuid(verge?.windows_ics_private_adapter_guid ?? '')
        setIcsPrivateName(verge?.windows_ics_private_adapter_name ?? '')
        void loadIcsConnections()
      }
    },
    close: () => setOpen(false),
  }))

  const tunConnectionName = values.device.trim() || 'Mihomo'
  const privateIcsConnections = icsConnections.filter(
    (connection) =>
      connection.name !== tunConnectionName &&
      connection.deviceName !== tunConnectionName,
  )

  const onRepairIcs = useLockFn(async () => {
    if (!icsPrivateGuid && !icsPrivateName) {
      showNotice.error('settings.modals.tun.messages.icsPrivateAdapterRequired')
      return
    }

    setIcsRepairing(true)
    try {
      const result = await repairWindowsIcs({
        publicConnection: { name: tunConnectionName },
        privateConnection: {
          guid: icsPrivateGuid || undefined,
          name: icsPrivateName || undefined,
        },
        forceRebind: true,
      })
      showNotice.success(
        result.changed
          ? 'settings.modals.tun.messages.icsRepaired'
          : 'settings.modals.tun.messages.icsAlreadyHealthy',
      )
    } catch (err: any) {
      showNotice.error(err)
    } finally {
      setIcsRepairing(false)
    }
  })

  const onSave = useLockFn(async () => {
    try {
      const routeExcludeAddress = routeExcludeAddressItems

      if (routeExcludeAddressError) {
        showNotice.error(
          'settings.modals.tun.messages.invalidRouteExcludeAddress',
        )
        return
      }
      if (
        OS === 'windows' &&
        icsAutoRecovery &&
        !icsPrivateGuid &&
        !icsPrivateName
      ) {
        showNotice.error(
          'settings.modals.tun.messages.icsPrivateAdapterRequired',
        )
        return
      }

      const tun: IConfigData['tun'] = {
        stack: values.stack,
        device:
          values.device === ''
            ? OS === 'macos'
              ? 'utun1024'
              : 'Mihomo'
            : values.device,
        'auto-route': values.autoRoute,
        'route-exclude-address': routeExcludeAddress,
        ...(OS === 'linux'
          ? {
              'auto-redirect': values.autoRedirect,
            }
          : {}),
        'auto-detect-interface': values.autoDetectInterface,
        'dns-hijack': values.dnsHijack[0] === '' ? [] : values.dnsHijack,
        'strict-route': values.strictRoute,
        mtu: values.mtu ?? 1500,
      }
      if (OS === 'windows') {
        await patchWindowsTunAndIcsConfig(tun, {
          enable_windows_ics_recovery: icsAutoRecovery,
          windows_ics_private_adapter_guid: icsPrivateGuid,
          windows_ics_private_adapter_name: icsPrivateName,
        })
        mutateVerge()
      } else {
        await patchClash({ tun })
      }
      await mutateClash(
        (old) => ({
          ...old!,
          tun,
        }),
        false,
      )
      setOpen(false)
      showNotice.success('settings.modals.tun.messages.applied')
      void enhanceProfiles().catch((err: any) => {
        showNotice.error(err)
      })
    } catch (err: any) {
      showNotice.error(err)
    }
  })

  return (
    <BaseDialog
      open={open}
      title={
        <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1 }}>
          <Typography variant="h6">{t('settings.modals.tun.title')}</Typography>
          <Button
            variant="outlined"
            size="small"
            onClick={async () => {
              const tun: IConfigData['tun'] = {
                stack: 'gvisor',
                device: OS === 'macos' ? 'utun1024' : 'Mihomo',
                'auto-route': true,
                ...(OS === 'linux'
                  ? {
                      'auto-redirect': false,
                    }
                  : {}),
                'auto-detect-interface': true,
                'dns-hijack': ['any:53'],
                'route-exclude-address': [],
                'strict-route': false,
                mtu: 1500,
              }
              setValues({
                stack: 'gvisor',
                device: OS === 'macos' ? 'utun1024' : 'Mihomo',
                autoRoute: true,
                routeExcludeAddress: '',
                autoRedirect: false,
                autoDetectInterface: true,
                dnsHijack: ['any:53'],
                strictRoute: false,
                mtu: 1500,
              })
              await patchClash({ tun })
              await mutateClash(
                (old) => ({
                  ...old!,
                  tun,
                }),
                false,
              )
            }}
          >
            {t('shared.actions.resetToDefault')}
          </Button>
        </Box>
      }
      contentSx={{ width: 450 }}
      okBtn={t('shared.actions.save')}
      cancelBtn={t('shared.actions.cancel')}
      onClose={() => setOpen(false)}
      onCancel={() => setOpen(false)}
      onOk={onSave}
    >
      <List>
        <ListItem sx={{ padding: '5px 2px' }}>
          <ListItemText primary={t('settings.modals.tun.fields.stack')} />
          <StackModeSwitch
            value={values.stack}
            onChange={(value) => {
              setValues((v) => ({
                ...v,
                stack: value,
              }))
            }}
          />
        </ListItem>

        <ListItem sx={{ padding: '5px 2px' }}>
          <ListItemText primary={t('settings.modals.tun.fields.device')} />
          <TextField
            autoComplete="new-password"
            size="small"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck="false"
            sx={{ width: 250 }}
            value={values.device}
            placeholder="Mihomo"
            onChange={(e) =>
              setValues((v) => ({ ...v, device: e.target.value }))
            }
          />
        </ListItem>

        <ListItem sx={{ padding: '5px 2px' }}>
          <ListItemText primary={t('settings.modals.tun.fields.autoRoute')} />
          <Switch
            edge="end"
            checked={values.autoRoute}
            onChange={(_, c) =>
              setValues((v) => ({
                ...v,
                autoRoute: c,
                autoRedirect: c ? v.autoRedirect : false,
              }))
            }
          />
        </ListItem>

        {OS === 'linux' && (
          <ListItem sx={{ padding: '5px 2px' }}>
            <ListItemText
              primary={t('settings.modals.tun.fields.autoRedirect')}
              sx={{ maxWidth: 'fit-content' }}
            />
            <TooltipIcon
              title={t('settings.modals.tun.tooltips.autoRedirect')}
              sx={{ opacity: values.autoRoute ? 0.7 : 0.3 }}
            />
            <Switch
              edge="end"
              checked={values.autoRedirect}
              onChange={(_, c) =>
                setValues((v) => ({
                  ...v,
                  autoRedirect: v.autoRoute ? c : v.autoRedirect,
                }))
              }
              disabled={!values.autoRoute}
              sx={{ marginLeft: 'auto' }}
            />
          </ListItem>
        )}

        <ListItem sx={{ padding: '5px 2px' }}>
          <ListItemText primary={t('settings.modals.tun.fields.strictRoute')} />
          <Switch
            edge="end"
            checked={values.strictRoute}
            onChange={(_, c) => setValues((v) => ({ ...v, strictRoute: c }))}
          />
        </ListItem>

        <ListItem sx={{ padding: '5px 2px' }}>
          <ListItemText
            primary={t('settings.modals.tun.fields.autoDetectInterface')}
          />
          <Switch
            edge="end"
            checked={values.autoDetectInterface}
            onChange={(_, c) =>
              setValues((v) => ({ ...v, autoDetectInterface: c }))
            }
          />
        </ListItem>

        <ListItem sx={{ padding: '5px 2px' }}>
          <ListItemText primary={t('settings.modals.tun.fields.dnsHijack')} />
          <TextField
            autoComplete="new-password"
            size="small"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck="false"
            sx={{ width: 250 }}
            value={values.dnsHijack.join(',')}
            placeholder={t('settings.modals.tun.tooltips.dnsHijack')}
            onChange={(e) =>
              setValues((v) => ({ ...v, dnsHijack: e.target.value.split(',') }))
            }
          />
        </ListItem>

        <ListItem sx={{ padding: '5px 2px' }}>
          <ListItemText primary={t('settings.modals.tun.fields.mtu')} />
          <TextField
            autoComplete="new-password"
            size="small"
            type="number"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck="false"
            sx={{ width: 250 }}
            value={values.mtu}
            placeholder="1500"
            onChange={(e) =>
              setValues((v) => ({
                ...v,
                mtu: parseInt(e.target.value),
              }))
            }
          />
        </ListItem>

        <BaseSplitChipEditor
          value={values.routeExcludeAddress}
          placeholder="192.168.0.0/16"
          ariaLabel={t('settings.modals.tun.fields.routeExcludeAddress')}
          disabled={!values.autoRoute}
          error={routeExcludeAddressError}
          helperText={routeExcludeAddressHelperText}
          onChange={(nextValue) =>
            setValues((v) => ({ ...v, routeExcludeAddress: nextValue }))
          }
          renderHeader={(modeToggle) => (
            <ListItem sx={{ padding: '5px 2px' }}>
              <ListItemText
                primary={t('settings.modals.tun.fields.routeExcludeAddress')}
              />
              {modeToggle ? (
                <Box sx={{ marginLeft: 'auto' }}>{modeToggle}</Box>
              ) : null}
            </ListItem>
          )}
        />

        {OS === 'windows' && (
          <>
            <ListItem sx={{ padding: '12px 2px 5px' }}>
              <ListItemText
                primary={t('settings.modals.tun.fields.icsRecovery')}
                secondary={t('settings.modals.tun.tooltips.icsRecovery')}
              />
              <Switch
                edge="end"
                checked={icsAutoRecovery}
                onChange={(_, checked) => setIcsAutoRecovery(checked)}
              />
            </ListItem>

            <ListItem sx={{ padding: '5px 2px', gap: 1 }}>
              <ListItemText
                primary={t('settings.modals.tun.fields.icsPrivateAdapter')}
              />
              <TextField
                select
                size="small"
                sx={{ width: 250 }}
                value={icsPrivateGuid}
                disabled={icsConnectionsLoading}
                onChange={(event) => {
                  const connection = icsConnections.find(
                    (item) => item.guid === event.target.value,
                  )
                  setIcsPrivateGuid(event.target.value)
                  setIcsPrivateName(connection?.name ?? '')
                }}
              >
                {icsPrivateGuid &&
                  !privateIcsConnections.some(
                    (connection) => connection.guid === icsPrivateGuid,
                  ) && (
                    <MenuItem value={icsPrivateGuid}>
                      {icsPrivateName || icsPrivateGuid}
                    </MenuItem>
                  )}
                {privateIcsConnections.map((connection) => (
                  <MenuItem key={connection.guid} value={connection.guid}>
                    {connection.name}
                  </MenuItem>
                ))}
              </TextField>
              <Button
                size="small"
                disabled={icsConnectionsLoading}
                onClick={() => void loadIcsConnections()}
              >
                {t('settings.modals.tun.actions.icsRefreshAdapters')}
              </Button>
            </ListItem>

            <ListItem sx={{ padding: '5px 2px', justifyContent: 'flex-end' }}>
              <Button
                variant="outlined"
                disabled={icsRepairing || (!icsPrivateGuid && !icsPrivateName)}
                onClick={onRepairIcs}
              >
                {t('settings.modals.tun.actions.icsRepairNow')}
              </Button>
            </ListItem>
          </>
        )}
      </List>
    </BaseDialog>
  )
}
