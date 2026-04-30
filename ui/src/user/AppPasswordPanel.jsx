import React, { useCallback, useEffect, useState } from 'react'
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@material-ui/core'
import DeleteOutlineIcon from '@material-ui/icons/DeleteOutline'
import FileCopyIcon from '@material-ui/icons/FileCopy'
import { useNotify, useTranslate } from 'react-admin'
import { makeStyles } from '@material-ui/core/styles'
import httpClient from '../dataProvider/httpClient'
import { REST_URL } from '../consts'

const useStyles = makeStyles((theme) => ({
  root: {
    width: '100%',
    marginTop: theme.spacing(3),
    padding: theme.spacing(2),
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: theme.spacing(1),
  },
  empty: {
    color: theme.palette.text.secondary,
    fontStyle: 'italic',
    padding: theme.spacing(2, 0),
  },
  secretField: {
    fontFamily: 'monospace',
    width: '100%',
  },
  secretActions: {
    display: 'flex',
    alignItems: 'center',
    marginTop: theme.spacing(1),
  },
}))

// AppPasswordPanel renders a list of the user's app passwords with a button to
// generate a new one and a per-row revoke button. The plaintext secret is
// shown exactly once, in a modal, immediately after generation. After the
// modal is dismissed the secret is unrecoverable from the UI.
export const AppPasswordPanel = ({ userId }) => {
  const classes = useStyles()
  const translate = useTranslate()
  const notify = useNotify()

  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  const [generated, setGenerated] = useState(null)

  const reload = useCallback(async () => {
    if (!userId) return
    setLoading(true)
    try {
      const { json } = await httpClient(
        `${REST_URL}/user/${userId}/app-password`,
      )
      setItems(Array.isArray(json) ? json : [])
    } catch (e) {
      notify('resources.user.notifications.appPasswordLoadError', 'warning')
    } finally {
      setLoading(false)
    }
  }, [userId, notify])

  useEffect(() => {
    reload()
  }, [reload])

  const handleCreate = async () => {
    if (!newName.trim()) return
    setCreating(true)
    try {
      const { json } = await httpClient(
        `${REST_URL}/user/${userId}/app-password`,
        {
          method: 'POST',
          body: JSON.stringify({ name: newName.trim() }),
        },
      )
      setGenerated(json)
      setCreateOpen(false)
      setNewName('')
      await reload()
    } catch (e) {
      const msg =
        e?.body?.toString?.() ||
        e?.message ||
        translate('resources.user.notifications.appPasswordCreateError')
      notify(msg, 'warning')
    } finally {
      setCreating(false)
    }
  }

  const handleRevoke = async (id) => {
    try {
      await httpClient(`${REST_URL}/user/${userId}/app-password/${id}`, {
        method: 'DELETE',
      })
      notify('resources.user.notifications.appPasswordRevoked', 'info')
      await reload()
    } catch (e) {
      notify('resources.user.notifications.appPasswordRevokeError', 'warning')
    }
  }

  const handleCopy = (value) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(value)
      notify('resources.user.notifications.appPasswordCopied', 'info')
    }
  }

  const formatDate = (d) => (d ? new Date(d).toLocaleString() : '—')

  return (
    <Paper className={classes.root} elevation={0} variant="outlined">
      <Box className={classes.header}>
        <Typography variant="h6">
          {translate('resources.user.fields.appPasswords')}
        </Typography>
        <Button
          variant="contained"
          color="primary"
          onClick={() => setCreateOpen(true)}
        >
          {translate('resources.user.actions.generateAppPassword')}
        </Button>
      </Box>

      {!loading && items.length === 0 && (
        <Typography className={classes.empty}>
          {translate('resources.user.message.appPasswordsEmpty')}
        </Typography>
      )}

      {items.length > 0 && (
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>
                {translate('resources.user.fields.appPasswordName')}
              </TableCell>
              <TableCell>
                {translate('resources.user.fields.appPasswordCreatedAt')}
              </TableCell>
              <TableCell>
                {translate('resources.user.fields.appPasswordLastUsedAt')}
              </TableCell>
              <TableCell>
                {translate('resources.user.fields.appPasswordStatus')}
              </TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {items.map((row) => (
              <TableRow key={row.id}>
                <TableCell>{row.name}</TableCell>
                <TableCell>{formatDate(row.createdAt)}</TableCell>
                <TableCell>{formatDate(row.lastUsedAt)}</TableCell>
                <TableCell>
                  {row.revokedAt
                    ? translate('resources.user.message.appPasswordRevoked')
                    : translate('resources.user.message.appPasswordActive')}
                </TableCell>
                <TableCell align="right">
                  {!row.revokedAt && (
                    <Tooltip
                      title={translate(
                        'resources.user.actions.revokeAppPassword',
                      )}
                    >
                      <IconButton
                        size="small"
                        onClick={() => handleRevoke(row.id)}
                      >
                        <DeleteOutlineIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog
        open={createOpen}
        onClose={() => !creating && setCreateOpen(false)}
      >
        <DialogTitle>
          {translate('resources.user.actions.generateAppPassword')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {translate('resources.user.message.appPasswordCreatePrompt')}
          </DialogContentText>
          <TextField
            autoFocus
            fullWidth
            margin="dense"
            label={translate('resources.user.fields.appPasswordName')}
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            disabled={creating}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} disabled={creating}>
            {translate('ra.action.cancel')}
          </Button>
          <Button
            onClick={handleCreate}
            color="primary"
            disabled={creating || !newName.trim()}
          >
            {translate('ra.action.create')}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!generated} onClose={() => setGenerated(null)} fullWidth>
        <DialogTitle>
          {translate('resources.user.message.appPasswordCreated')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {translate('resources.user.message.appPasswordOneTime')}
          </DialogContentText>
          {generated && (
            <>
              <TextField
                value={generated.secret}
                className={classes.secretField}
                InputProps={{ readOnly: true }}
                onFocus={(e) => e.target.select()}
                multiline
              />
              <Box className={classes.secretActions}>
                <Button
                  startIcon={<FileCopyIcon />}
                  onClick={() => handleCopy(generated.secret)}
                >
                  {translate('resources.user.actions.copyAppPassword')}
                </Button>
              </Box>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setGenerated(null)} color="primary">
            {translate('ra.action.close')}
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  )
}

export default AppPasswordPanel
