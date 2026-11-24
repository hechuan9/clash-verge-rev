import {
  Alert,
  Box,
  Button,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useEffect, useState } from 'react'

import { BasePage } from '@/components/base'
import type { HomeEgressView } from '@/services/bindings'
import { getHomeEgress, saveHomeEgress } from '@/services/cmds'
import { mutate } from '@/services/mutate'

function detail(error: unknown) {
  if (error && typeof error === 'object' && 'detail' in error)
    return String(error.detail)
  return String(error)
}

function domainsFromText(input: string) {
  const entries = input
    .split(/\s+/)
    .filter(Boolean)
    .map((entry) => {
      if (/^https?:\/\//i.test(entry))
        return new URL(entry).hostname.toLowerCase()
      return entry.toLowerCase()
    })
  return [...new Set(entries)]
}

export default function HomeEgressPage() {
  const [view, setView] = useState<HomeEgressView | null>(null)
  const [carrier, setCarrier] = useState('')
  const [domains, setDomains] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  const load = async () => {
    const next = await getHomeEgress()
    setView(next)
    setCarrier(next.carrier ?? '')
    setDomains(next.domains.join('\n'))
  }
  useEffect(() => {
    void load().catch((e) => setError(detail(e)))
  }, [])

  const apply = async () => {
    setBusy(true)
    setSaved(false)
    setError('')
    try {
      const ovpn = file ? await file.text() : null
      await mutate(
        () => saveHomeEgress(carrier, domainsFromText(domains), ovpn),
        {
          id: 'save-home-egress',
          errorNotice: false,
        },
      )
      setFile(null)
      await load()
      setSaved(true)
    } catch (e) {
      setError(detail(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <BasePage title="家庭出口">
      <Stack
        spacing={2.5}
        sx={{ maxWidth: 640, p: 2 }}
        onChange={() => setSaved(false)}
      >
        <Typography>
          清单内的站点通过所选策略组连接家中 Deco。其他站点使用订阅原有规则。
        </Typography>
        {error && <Alert severity="error">{error}</Alert>}
        {saved && <Alert severity="success">分流配置已应用</Alert>}
        <TextField
          select
          label="VPN 前置策略组"
          helperText="在「代理」页切换节点，VPN 下次建隧道时跟随所选策略组。前置节点须支持 UDP。"
          value={carrier}
          disabled={busy || !view}
          onChange={(e) => {
            setCarrier(e.target.value)
            setSaved(false)
          }}
        >
          {carrier && view && !view.candidates.includes(carrier) && (
            <MenuItem value={carrier} disabled>
              {carrier}（请改选可用策略组）
            </MenuItem>
          )}
          {(view?.candidates ?? []).map((name) => (
            <MenuItem key={name} value={name}>
              {name}
            </MenuItem>
          ))}
        </TextField>
        <Box>
          <Typography variant="body2" sx={{ mb: 1 }}>
            家庭 OpenVPN · {file?.name ?? view?.server ?? '尚未导入'}
          </Typography>
          <Button component="label" variant="outlined" disabled={busy}>
            导入 Deco .ovpn
            <input
              hidden
              type="file"
              accept=".ovpn"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null)
                e.target.value = ''
                setSaved(false)
              }}
            />
          </Button>
        </Box>
        <TextField
          multiline
          minRows={7}
          label="使用家庭出口的站点"
          value={domains}
          disabled={busy}
          helperText="每行一个域名或 URL。*.claude.ai 包含主域名及所有子域名。"
          onChange={(e) => setDomains(e.target.value)}
        />
        <Box>
          <Button
            variant="contained"
            onClick={() => void apply()}
            disabled={busy || !carrier || (!view?.server && !file)}
          >
            {busy ? '正在应用…' : '应用配置'}
          </Button>
        </Box>
      </Stack>
    </BasePage>
  )
}
